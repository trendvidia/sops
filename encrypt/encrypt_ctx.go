// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package encrypt

import (
	"context"
	"fmt"
	"os"

	"github.com/trendvidia/sops/v4"
	"github.com/trendvidia/sops/v4/aes"
	"github.com/trendvidia/sops/v4/cmd/sops/common"
	. "github.com/trendvidia/sops/v4/cmd/sops/formats" // Re-export
	"github.com/trendvidia/sops/v4/config"
	"github.com/trendvidia/sops/v4/keyservice"
	"github.com/trendvidia/sops/v4/version"
)

// DataWithContext is the context-aware sibling of [Data]. The ctx
// propagates through the data-key generation path so cancellation
// terminates in-flight KMS round-trips (gRPC-served keyservices honor
// ctx natively; the in-process default keyservice does as of v3.13.2).
func DataWithContext(ctx context.Context, plaintext []byte, format string, opts Options) ([]byte, error) {
	return DataWithFormatContext(ctx, plaintext, FormatFromString(format), opts)
}

// DataWithFormatContext is the typed-format sibling of [DataWithContext].
func DataWithFormatContext(ctx context.Context, plaintext []byte, format Format, opts Options) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("encrypt: context already cancelled: %w", err)
	}
	if len(opts.KeyGroups) == 0 {
		return nil, fmt.Errorf("encrypt: at least one KeyGroup is required")
	}

	inStore := common.StoreForFormat(format, config.NewStoresConfig())
	outStore := inStore

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

	dataKey, errs := tree.GenerateDataKeyCtxWithKeyServices(ctx, svcs)
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

// FileWithContext is the context-aware sibling of [File].
func FileWithContext(ctx context.Context, inPath, outPath, format string, opts Options) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("encrypt: context already cancelled: %w", err)
	}
	plaintext, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("encrypt: read %q: %w", inPath, err)
	}
	if _, err := os.Stat(outPath); err == nil {
		return fmt.Errorf("encrypt: refusing to overwrite existing %q", outPath)
	}
	formatFmt := FormatForPathOrString(inPath, format)
	ciphertext, err := DataWithFormatContext(ctx, plaintext, formatFmt, opts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, ciphertext, 0o600); err != nil {
		return fmt.Errorf("encrypt: write %q: %w", outPath, err)
	}
	return nil
}

// UsingSameKeysAsWithContext is the context-aware sibling of
// [UsingSameKeysAs].
func UsingSameKeysAsWithContext(ctx context.Context, plaintext, ciphertextRef []byte, format string) ([]byte, error) {
	return UsingSameKeysAsWithFormatContext(ctx, plaintext, ciphertextRef, FormatFromString(format))
}

// UsingSameKeysAsWithFormatContext is the typed-format sibling.
func UsingSameKeysAsWithFormatContext(ctx context.Context, plaintext, ciphertextRef []byte, format Format) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("encrypt: context already cancelled: %w", err)
	}
	refStore := common.StoreForFormat(format, config.NewStoresConfig())
	refTree, err := refStore.LoadEncryptedFile(ciphertextRef)
	if err != nil {
		return nil, fmt.Errorf("encrypt: load reference ciphertext: %w", err)
	}

	opts := Options{
		KeyGroups:               refTree.Metadata.KeyGroups,
		ShamirThreshold:         refTree.Metadata.ShamirThreshold,
		EncryptedSuffix:         refTree.Metadata.EncryptedSuffix,
		EncryptedRegex:          refTree.Metadata.EncryptedRegex,
		UnencryptedSuffix:       refTree.Metadata.UnencryptedSuffix,
		UnencryptedRegex:        refTree.Metadata.UnencryptedRegex,
		EncryptedCommentRegex:   refTree.Metadata.EncryptedCommentRegex,
		UnencryptedCommentRegex: refTree.Metadata.UnencryptedCommentRegex,
		MACOnlyEncrypted:        refTree.Metadata.MACOnlyEncrypted,
	}
	return DataWithFormatContext(ctx, plaintext, format, opts)
}
