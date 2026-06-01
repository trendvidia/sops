// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package encrypt_test

import (
	"strings"
	"testing"

	"github.com/trendvidia/sops/v4"
	"github.com/trendvidia/sops/v4/age"
	"github.com/trendvidia/sops/v4/decrypt"
	"github.com/trendvidia/sops/v4/encrypt"
)

const (
	// Stable test recipient + identity pair from age/keysource_test.go.
	testRecipient = "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"
	testIdentity  = "AGE-SECRET-KEY-1G0Q5K9TV4REQ3ZSQRMTMG8NSWQGYT0T7TZ33RAZEE0GZYVZN0APSU24RK7"
)

func ageKeyGroup(t *testing.T) sops.KeyGroup {
	t.Helper()
	mk, err := age.MasterKeyFromRecipient(testRecipient)
	if err != nil {
		t.Fatalf("age.MasterKeyFromRecipient: %v", err)
	}
	return sops.KeyGroup{mk}
}

func TestData_RoundTripAge_Yaml(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", testIdentity)

	// Unquoted values: sops's YAML emitter strips redundant quotes so
	// byte-identical round-trip requires starting unquoted.
	plaintext := []byte(`name: production-db
host: db.internal
password: supersecret
port: 5432
`)
	ciphertext, err := encrypt.Data(plaintext, "yaml", encrypt.Options{
		KeyGroups:         []sops.KeyGroup{ageKeyGroup(t)},
		UnencryptedSuffix: "_plain",
	})
	if err != nil {
		t.Fatalf("encrypt.Data: %v", err)
	}
	if !strings.Contains(string(ciphertext), "sops:") {
		t.Fatalf("ciphertext does not contain sops metadata stanza:\n%s", ciphertext)
	}

	recovered, err := decrypt.Data(ciphertext, "yaml")
	if err != nil {
		t.Fatalf("decrypt.Data: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Errorf("round-trip mismatch:\n--- plaintext ---\n%s\n--- recovered ---\n%s", plaintext, recovered)
	}
}

func TestData_RoundTripAge_Json(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", testIdentity)

	plaintext := []byte(`{"name":"production-db","host":"db.internal","password":"supersecret","port":5432}`)
	ciphertext, err := encrypt.Data(plaintext, "json", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroup(t)},
	})
	if err != nil {
		t.Fatalf("encrypt.Data: %v", err)
	}

	recovered, err := decrypt.Data(ciphertext, "json")
	if err != nil {
		t.Fatalf("decrypt.Data: %v", err)
	}
	// JSON output may re-emit with different whitespace; compare the
	// payload-bearing substrings tolerantly.
	collapsed := strings.Join(strings.Fields(string(recovered)), "")
	for _, want := range []string{`"password":"supersecret"`, `"host":"db.internal"`} {
		if !strings.Contains(collapsed, want) {
			t.Errorf("recovered missing %q:\n%s", want, recovered)
		}
	}
}

func TestData_NoKeyGroups_Error(t *testing.T) {
	_, err := encrypt.Data([]byte(`x: y`), "yaml", encrypt.Options{})
	if err == nil {
		t.Fatal("expected error for empty KeyGroups; got nil")
	}
	if !strings.Contains(err.Error(), "KeyGroup") {
		t.Errorf("error should mention KeyGroup, got: %v", err)
	}
}

func TestUsingSameKeysAs_PreservesRecipients(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", testIdentity)

	// 1. Encrypt the reference with a specific key set + suffix rule.
	refPlain := []byte(`a: "1"
b: "secret"
`)
	refCiph, err := encrypt.Data(refPlain, "yaml", encrypt.Options{
		KeyGroups:         []sops.KeyGroup{ageKeyGroup(t)},
		UnencryptedSuffix: "_plain",
	})
	if err != nil {
		t.Fatalf("encrypt ref: %v", err)
	}

	// 2. Encrypt a different plaintext using the same key set.
	// Use unquoted YAML values so the round-trip is byte-identical
	// (yaml emitter strips redundant quotes).
	newPlain := []byte(`c: different
d: data
`)
	newCiph, err := encrypt.UsingSameKeysAs(newPlain, refCiph, "yaml")
	if err != nil {
		t.Fatalf("UsingSameKeysAs: %v", err)
	}

	// 3. Decrypt the new ciphertext with the same identity — proves
	// the key set was preserved.
	recovered, err := decrypt.Data(newCiph, "yaml")
	if err != nil {
		t.Fatalf("decrypt new: %v (key set was not preserved)", err)
	}
	if string(recovered) != string(newPlain) {
		t.Errorf("round-trip mismatch:\nwant: %q\ngot:  %q", newPlain, recovered)
	}
}
