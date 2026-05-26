package keypb

import (
	"fmt"
	"strings"

	"filippo.io/age"
)

// deriveRecipient returns the Bech32-encoded age public key for a
// parsed identity secret string. Returns "" with a nil error for
// plugin identities (recipient derivation requires the plugin's IPC
// protocol — out of scope for this package).
func deriveRecipient(secret string) (string, error) {
	switch {
	case strings.HasPrefix(secret, "AGE-PLUGIN-"):
		return "", nil
	case strings.HasPrefix(secret, "AGE-SECRET-KEY-PQ-1"):
		id, err := age.ParseHybridIdentity(secret)
		if err != nil {
			return "", err
		}
		return id.Recipient().String(), nil
	case strings.HasPrefix(secret, "AGE-SECRET-KEY-1"):
		id, err := age.ParseX25519Identity(secret)
		if err != nil {
			return "", err
		}
		return id.Recipient().String(), nil
	default:
		return "", fmt.Errorf("unknown age identity type")
	}
}

// Recipients returns a map from entry name to the Bech32-encoded
// public key derived from that entry's X25519 or hybrid secret.
// Entries whose secret is a plugin identity are silently skipped
// (their recipient derivation goes through the plugin's IPC
// protocol, which isn't appropriate to drive from this package).
// Returns an error if any secret is malformed.
func (k *AgeKeyFile) Recipients() (map[string]string, error) {
	out := make(map[string]string, len(k.Keys))
	for name, secret := range k.Keys {
		r, err := deriveRecipient(secret)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", name, err)
		}
		if r != "" {
			out[name] = r
		}
	}
	return out, nil
}

// RecipientForName returns the Bech32-encoded public key for the
// named entry. Returns "" with a nil error if `name` isn't in the
// file, or if its secret is a plugin identity (no derivation). Errors
// only when the secret is present but malformed.
func (k *AgeKeyFile) RecipientForName(name string) (string, error) {
	secret, ok := k.Keys[name]
	if !ok {
		return "", nil
	}
	return deriveRecipient(secret)
}

// NameForRecipient returns the entry name whose derived public key
// matches `recipient`. Returns "" with a nil error if no entry
// matches. Errors only when a secret in the file is malformed.
func (k *AgeKeyFile) NameForRecipient(recipient string) (string, error) {
	for name, secret := range k.Keys {
		r, err := deriveRecipient(secret)
		if err != nil {
			return "", fmt.Errorf("entry %q: %w", name, err)
		}
		if r == recipient {
			return name, nil
		}
	}
	return "", nil
}
