// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package decrypt

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	. "github.com/getsops/sops/v3/cmd/sops/formats" // Re-export
	"github.com/getsops/sops/v3/config"
)

// FileWithContext is the context-aware sibling of [File]. The context is
// checked before the call begins and propagated through the data-key
// acquisition path so a cancelled or expired context aborts an in-flight
// keyservice call.
//
// Cancellation reaches the underlying KMS round-trip whenever the
// keyservice honors ctx — gRPC-served keyservices do natively, and the
// in-process default keyservice does as of v3.13.2.
func FileWithContext(ctx context.Context, path, format string) (cleartext []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("decrypt: context already cancelled: %w", err)
	}
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %q: %w", path, err)
	}
	formatFmt := FormatForPathOrString(path, format)
	return DataWithFormatContext(ctx, encryptedData, formatFmt)
}

// DataWithFormatContext is the context-aware sibling of [DataWithFormat].
// See [FileWithContext] for the current scope of ctx-honoring.
func DataWithFormatContext(ctx context.Context, data []byte, format Format) (cleartext []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("decrypt: context already cancelled: %w", err)
	}

	store := common.StoreForFormat(format, config.NewStoresConfig())

	// Load SOPS file and access the data key with ctx propagation.
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, err
	}
	key, err := tree.Metadata.GetDataKeyCtx(ctx)
	if err != nil {
		return nil, err
	}

	// Decrypt the tree.
	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return nil, err
	}

	// Compute the hash of the cleartext tree and compare it with the one
	// stored in the document. If they match, integrity was preserved.
	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		key,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt original mac: %w", err)
	}
	if originalMac != mac {
		return nil, fmt.Errorf("Failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
	}

	return store.EmitPlainFile(tree.Branches)
}

// DataWithContext is the context-aware sibling of [Data].
// See [FileWithContext] for the current scope of ctx-honoring.
func DataWithContext(ctx context.Context, data []byte, format string) (cleartext []byte, err error) {
	return DataWithFormatContext(ctx, data, FormatFromString(format))
}

// DataIntoWriter decrypts data and streams the plaintext directly to w
// instead of allocating a `[]byte` on the regular heap. Designed for
// consumers that want the decrypted output to land in mlocked memory
// (e.g. a memguard LockedBuffer wrapped as io.Writer) so the plaintext
// never resides on unprotected heap during the decrypt → consumer
// handoff. Format must be one of the strings recognized by
// [github.com/getsops/sops/v3/cmd/sops/formats.FormatFromString].
//
// Closure semantics: the FINAL plaintext (the emit-stage output) goes
// directly into w. Per-leaf plaintext strings still allocate on the
// regular heap during the AES-GCM decrypt walk in [sops.Tree.Decrypt]
// — closing that gap is a deeper Tree-restructure tracked separately
// (see trendvidia/chameleon#9 phase 2/3). For most consumers, the
// emit-stage allocation is by far the largest exposure window.
//
// Behavior on stores that don't implement [sops.PlainFileEmitterTo]:
// falls back to `EmitPlainFile` then `w.Write`. yaml / json / protowire
// implement the streaming variant; ini / dotenv currently do not.
func DataIntoWriter(w io.Writer, data []byte, format string) error {
	return DataIntoWriterFormatContext(context.Background(), w, data, FormatFromString(format))
}

// DataIntoWriterContext is the context-aware sibling of [DataIntoWriter].
func DataIntoWriterContext(ctx context.Context, w io.Writer, data []byte, format string) error {
	return DataIntoWriterFormatContext(ctx, w, data, FormatFromString(format))
}

// DataIntoWriterFormatContext is the typed-format sibling.
func DataIntoWriterFormatContext(ctx context.Context, w io.Writer, data []byte, format Format) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("decrypt: context already cancelled: %w", err)
	}

	store := common.StoreForFormat(format, config.NewStoresConfig())

	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return err
	}
	key, err := tree.Metadata.GetDataKeyCtx(ctx)
	if err != nil {
		return err
	}

	cipher := aes.NewCipher()
	mac, err := tree.Decrypt(key, cipher)
	if err != nil {
		return err
	}

	originalMac, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode,
		key,
		tree.Metadata.LastModified.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("Failed to decrypt original mac: %w", err)
	}
	if originalMac != mac {
		return fmt.Errorf("Failed to verify data integrity. expected mac %q, got %q", originalMac, mac)
	}

	// Prefer streaming emit if the store implements [sops.PlainFileEmitterTo].
	// Falls back to byte-emit + write for stores that don't.
	if emitter, ok := store.(sops.PlainFileEmitterTo); ok {
		return emitter.EmitPlainFileTo(w, tree.Branches)
	}
	plaintext, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return err
	}
	_, err = w.Write(plaintext)
	return err
}
