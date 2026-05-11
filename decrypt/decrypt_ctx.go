// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package decrypt

import (
	"context"
	"fmt"
	"os"
	"time"

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
