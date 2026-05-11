// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package decrypt

import (
	"context"
	"fmt"
	"os"

	. "github.com/getsops/sops/v3/cmd/sops/formats" // Re-export
)

// FileWithContext is the context-aware sibling of [File]. The context
// is checked before the call begins and (once every key service grows
// a ctx-aware Decrypt variant — see the MasterKeyCtx interface and
// follow-up PRs in this branch) propagated into each KMS round-trip
// so a cancelled or expired context aborts the decrypt cleanly.
//
// Until ctx-threading is complete in every key service, callers see
// "context honored before the decrypt call begins; not honored mid-
// call." That still beats the non-ctx API where a hung KMS round-trip
// blocks indefinitely.
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
	// TODO(trendvidia/sops#<this-PR>): plumb ctx into the key-service
	// loop in Metadata.GetDataKey so KMS calls accept cancellation.
	// Today the ctx check above is the only honoring point; once each
	// keysource implements MasterKeyCtx (a sibling interface to
	// MasterKey adding DecryptCtx(ctx)), GetDataKeyCtx will call the
	// ctx-aware variant when available and fall back to the
	// non-ctx Decrypt otherwise.
	return DataWithFormat(data, format)
}

// DataWithContext is the context-aware sibling of [Data].
// See [FileWithContext] for the current scope of ctx-honoring.
func DataWithContext(ctx context.Context, data []byte, format string) (cleartext []byte, err error) {
	return DataWithFormatContext(ctx, data, FormatFromString(format))
}
