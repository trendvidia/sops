// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

// Package encrypt is the external API other Go programs can use to
// encrypt SOPS files programmatically. Mirrors the surface of the
// existing [github.com/getsops/sops/v3/decrypt] package.
//
// Why it exists: until this package, programmatic encryption required
// importing [github.com/getsops/sops/v3/cmd/sops/common.EncryptTree]
// and wiring up keygroups, ciphers, and stores by hand. That works,
// but `cmd/sops/common` is semantically internal — its API surface
// is treated as an implementation detail of the CLI. The encrypt
// package promotes the load → datakey → encrypt → emit pipeline into
// a stable, documented top-level surface that mirrors decrypt's
// Data / File / DataWithFormat entry points.
//
// Stability: this package follows sops's broader stability promise.
// Callers that want fine-grained control (mid-encrypt hooks, partial
// trees, etc.) should drop down to `cmd/sops/common` — that surface
// remains as-is.
package encrypt

import (
	"fmt"
	"os"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	. "github.com/getsops/sops/v3/cmd/sops/formats" // Re-export
	"github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/version"
)

// Options configures a single encrypt call. Mirrors the relevant
// subset of [cmd/sops/common.EncryptTreeOpts] plus the metadata fields
// the CLI's encryptConfig builds.
//
// At least one KeyGroup with at least one MasterKey is required.
//
// EncryptedSuffix / EncryptedRegex / UnencryptedSuffix / UnencryptedRegex
// follow the existing sops semantics for selecting which fields get
// encrypted. The trendvidia fork additionally recognizes
// `# sops:encrypted` and `# sops:unencrypted` comment directives in
// formats that preserve comments (yaml, protowire/pxf, ini).
type Options struct {
	// KeyGroups is the set of master-key groups that can decrypt the
	// produced ciphertext. Each group's keys are summed via Shamir
	// secret sharing if ShamirThreshold > 0; otherwise each key alone
	// can decrypt.
	KeyGroups []sops.KeyGroup

	// ShamirThreshold, if > 0, configures Shamir secret sharing across
	// KeyGroups: a decryptor needs this many groups' keys to recover.
	ShamirThreshold int

	// EncryptedSuffix selects fields for encryption by name suffix
	// (e.g. "_encrypted"). Mutually exclusive with EncryptedRegex,
	// UnencryptedSuffix, UnencryptedRegex.
	EncryptedSuffix string

	// EncryptedRegex selects fields for encryption by name regex.
	EncryptedRegex string

	// UnencryptedSuffix selects fields to LEAVE PLAIN by name suffix.
	UnencryptedSuffix string

	// UnencryptedRegex selects fields to LEAVE PLAIN by name regex.
	UnencryptedRegex string

	// EncryptedCommentRegex / UnencryptedCommentRegex select fields by
	// regex matched against the field's leading comment.
	EncryptedCommentRegex   string
	UnencryptedCommentRegex string

	// MACOnlyEncrypted limits the MAC computation to encrypted fields
	// only (default: all fields).
	MACOnlyEncrypted bool

	// KeyServices override the default (local) key service.
	// If nil, a single local KeyService is used.
	KeyServices []keyservice.KeyServiceClient
}

// Data encrypts plaintext in the named format using opts and returns
// the ciphertext bytes. Format must be one of the strings recognized
// by [github.com/getsops/sops/v3/cmd/sops/formats.FormatFromString]
// (json, yaml, ini, dotenv, binary, protowire/pxf).
func Data(plaintext []byte, format string, opts Options) ([]byte, error) {
	return DataWithFormat(plaintext, FormatFromString(format), opts)
}

// DataWithFormat is the typed-format sibling of [Data].
func DataWithFormat(plaintext []byte, format Format, opts Options) ([]byte, error) {
	if len(opts.KeyGroups) == 0 {
		return nil, fmt.Errorf("encrypt: at least one KeyGroup is required")
	}

	inStore := common.StoreForFormat(format, config.NewStoresConfig())
	outStore := inStore // same format for encrypt; round-trip preserves shape.

	branches, err := inStore.LoadPlainFile(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt: load plaintext: %w", err)
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:               opts.KeyGroups,
			ShamirThreshold:         opts.ShamirThreshold,
			EncryptedSuffix:         opts.EncryptedSuffix,
			EncryptedRegex:          opts.EncryptedRegex,
			UnencryptedSuffix:       opts.UnencryptedSuffix,
			UnencryptedRegex:        opts.UnencryptedRegex,
			EncryptedCommentRegex:   opts.EncryptedCommentRegex,
			UnencryptedCommentRegex: opts.UnencryptedCommentRegex,
			MACOnlyEncrypted:        opts.MACOnlyEncrypted,
			Version:                 version.Version,
		},
	}

	svcs := opts.KeyServices
	if len(svcs) == 0 {
		svcs = []keyservice.KeyServiceClient{
			keyservice.NewLocalClient(),
		}
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(svcs)
	if len(errs) > 0 {
		return nil, fmt.Errorf("encrypt: generate data key: %v", errs)
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
		DataKey: dataKey,
	}); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	encrypted, err := outStore.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("encrypt: emit: %w", err)
	}
	return encrypted, nil
}

// File reads plaintext from inPath, encrypts it, and writes ciphertext
// to outPath. Format is inferred from inPath's extension unless
// explicitly set. Returns an error if outPath already exists (callers
// should remove or rename first to avoid silent overwrite).
func File(inPath, outPath, format string, opts Options) error {
	plaintext, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("encrypt: read %q: %w", inPath, err)
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("encrypt: refusing to overwrite existing %q", outPath)
	}
	formatFmt := FormatForPathOrString(inPath, format)
	ciphertext, err := DataWithFormat(plaintext, formatFmt, opts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("encrypt: write %q: %w", outPath, err)
	}
	return nil
}
