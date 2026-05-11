// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package encrypt_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/encrypt"
)

func ageKeyGroupForCtx(t *testing.T) sops.KeyGroup {
	t.Helper()
	mk, err := age.MasterKeyFromRecipient(testRecipient)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	return sops.KeyGroup{mk}
}

func TestDataWithContext_PreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := encrypt.DataWithContext(ctx, []byte("x: y"), "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroupForCtx(t)},
	})
	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

func TestDataWithContext_HappyPathAgeRoundTrip(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", testIdentity)

	plaintext := []byte("payload: ok\n")
	ciphertext, err := encrypt.DataWithContext(context.Background(), plaintext, "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroupForCtx(t)},
	})
	if err != nil {
		t.Fatalf("encrypt.DataWithContext: %v", err)
	}
	if !strings.Contains(string(ciphertext), "sops:") {
		t.Fatalf("ciphertext missing sops metadata stanza:\n%s", ciphertext)
	}
	recovered, err := decrypt.DataWithContext(context.Background(), ciphertext, "yaml")
	if err != nil {
		t.Fatalf("decrypt.DataWithContext: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Errorf("round-trip mismatch:\nwant: %q\ngot:  %q", plaintext, recovered)
	}
}

func TestUsingSameKeysAsWithContext_PreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := encrypt.UsingSameKeysAsWithContext(ctx, []byte("x"), []byte("y"), "yaml")
	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

func TestUsingSameKeysAsWithContext_PreservesRecipientsCtxPath(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", testIdentity)

	refPlain := []byte("a: 1\nb: secret\n")
	refCiph, err := encrypt.DataWithContext(context.Background(), refPlain, "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroupForCtx(t)},
	})
	if err != nil {
		t.Fatalf("encrypt ref: %v", err)
	}

	newPlain := []byte("c: different\nd: data\n")
	newCiph, err := encrypt.UsingSameKeysAsWithContext(context.Background(), newPlain, refCiph, "yaml")
	if err != nil {
		t.Fatalf("UsingSameKeysAsWithContext: %v", err)
	}

	recovered, err := decrypt.DataWithContext(context.Background(), newCiph, "yaml")
	if err != nil {
		t.Fatalf("decrypt new: %v (key set was not preserved)", err)
	}
	if string(recovered) != string(newPlain) {
		t.Errorf("round-trip mismatch:\nwant: %q\ngot:  %q", newPlain, recovered)
	}
}
