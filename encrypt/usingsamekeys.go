// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package encrypt

import (
	"fmt"

	"github.com/getsops/sops/v3/cmd/sops/common"
	. "github.com/getsops/sops/v3/cmd/sops/formats" // Re-export
	"github.com/getsops/sops/v3/config"
)

// UsingSameKeysAs encrypts plaintext using the same key set, shamir
// threshold, and suffix/regex rules as ciphertextRef — an existing
// encrypted sops document the caller wants to mirror. The format
// applies to both inputs.
//
// Use case: bulk-edit workflows that decrypt a file, mutate the
// plaintext, and re-encrypt with the original recipients without the
// caller having to extract metadata by hand. Drives the
// [chameleon migrate] CLI.
//
// [chameleon migrate]: https://github.com/trendvidia/chameleon/issues/5
func UsingSameKeysAs(plaintext, ciphertextRef []byte, format string) ([]byte, error) {
	return UsingSameKeysAsWithFormat(plaintext, ciphertextRef, FormatFromString(format))
}

// UsingSameKeysAsWithFormat is the typed-format sibling.
func UsingSameKeysAsWithFormat(plaintext, ciphertextRef []byte, format Format) ([]byte, error) {
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
	return DataWithFormat(plaintext, format, opts)
}
