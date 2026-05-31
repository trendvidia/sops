// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package encrypt

import (
	"context"
	"fmt"
	"io"

	. "github.com/trendvidia/sops/v3/cmd/sops/formats" // Re-export
)

// DataFromReader reads plaintext from r, encrypts it under opts, and
// returns the ciphertext. Symmetric to [github.com/trendvidia/sops/v3/decrypt.DataIntoWriter]
// on the decrypt side.
//
// Note on memory residency. Chameleon-style consumers that hold plaintext
// in mlocked memory (e.g. a memguard LockedBuffer) can equivalently call
// [Data] / [DataWithContext] passing `mlockedBuf.Bytes()` directly —
// slices into mlocked memory pass by reference without copying, so the
// plaintext stays mlock-resident through the load phase. The Reader-based
// API is for io.Reader sources where you don't already have a []byte in
// hand (stdin, network, files) and for API symmetry with the decrypt
// side's DataIntoWriter.
//
// Per-field plaintext strings (during yaml/json/pxf parse) still allocate
// on the regular heap. Closing that gap is the protowire-go Secret-direct
// decode work tracked in chameleon#7 (phase 2 of chameleon#9).
func DataFromReader(r io.Reader, format string, opts Options) ([]byte, error) {
	return DataFromReaderFormatContext(context.Background(), r, FormatFromString(format), opts)
}

// DataFromReaderContext is the context-aware sibling of [DataFromReader].
func DataFromReaderContext(ctx context.Context, r io.Reader, format string, opts Options) ([]byte, error) {
	return DataFromReaderFormatContext(ctx, r, FormatFromString(format), opts)
}

// DataFromReaderFormatContext is the typed-format sibling.
func DataFromReaderFormatContext(ctx context.Context, r io.Reader, format Format, opts Options) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("encrypt: context already cancelled: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("encrypt: read plaintext: %w", err)
	}
	return DataWithFormatContext(ctx, plaintext, format, opts)
}

// UsingSameKeysAsFromReader is the Reader-input sibling of
// [UsingSameKeysAs]. Reads plaintext from r and re-encrypts using the
// same key set as ciphertextRef.
func UsingSameKeysAsFromReader(r io.Reader, ciphertextRef []byte, format string) ([]byte, error) {
	return UsingSameKeysAsFromReaderFormatContext(context.Background(), r, ciphertextRef, FormatFromString(format))
}

// UsingSameKeysAsFromReaderContext is the context-aware sibling.
func UsingSameKeysAsFromReaderContext(ctx context.Context, r io.Reader, ciphertextRef []byte, format string) ([]byte, error) {
	return UsingSameKeysAsFromReaderFormatContext(ctx, r, ciphertextRef, FormatFromString(format))
}

// UsingSameKeysAsFromReaderFormatContext is the typed-format sibling.
func UsingSameKeysAsFromReaderFormatContext(ctx context.Context, r io.Reader, ciphertextRef []byte, format Format) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("encrypt: context already cancelled: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("encrypt: read plaintext: %w", err)
	}
	return UsingSameKeysAsWithFormatContext(ctx, plaintext, ciphertextRef, format)
}
