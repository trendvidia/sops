// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package encrypt_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/trendvidia/sops/v3"
	"github.com/trendvidia/sops/v3/decrypt"
	"github.com/trendvidia/sops/v3/encrypt"
)

// TestDataFromReader_ProducesBytewiseIdenticalOutput proves that
// DataFromReader yields ciphertext that decrypts to the same plaintext
// as Data() with the same input bytes.
//
// We can't compare ciphertexts byte-for-byte (each encrypt randomizes
// the data key) — but a decrypt round-trip is the right behavioral
// check.
func TestDataFromReader_ProducesEquivalentOutput(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", testIdentity)

	// Flat structure — yaml re-emission preserves it byte-for-byte.
	// Nested structures get re-indented (yaml emitter default ≠ 2-space).
	plaintext := []byte("payload: ok\nkey: value\n")

	// Subject under test.
	ciphertext, err := encrypt.DataFromReader(bytes.NewReader(plaintext), "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroupForCtx(t)},
	})
	if err != nil {
		t.Fatalf("DataFromReader: %v", err)
	}

	// Decrypt round-trip.
	recovered, err := decrypt.Data(ciphertext, "yaml")
	if err != nil {
		t.Fatalf("decrypt.Data: %v", err)
	}
	if !bytes.Equal(plaintext, recovered) {
		t.Errorf("plaintext mismatch:\nwant: %q\ngot:  %q", plaintext, recovered)
	}
}

func TestDataFromReaderContext_PreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := encrypt.DataFromReaderContext(ctx, strings.NewReader("x: y"), "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroupForCtx(t)},
	})
	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

func TestDataFromReader_ReaderErrorPropagates(t *testing.T) {
	bad := errors.New("synthetic reader error")
	_, err := encrypt.DataFromReader(&errReader{err: bad}, "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroupForCtx(t)},
	})
	if err == nil {
		t.Fatal("expected error from failing reader")
	}
	if !errors.Is(err, bad) {
		t.Errorf("err = %v; want %v in chain", err, bad)
	}
}

func TestUsingSameKeysAsFromReader_PreservesRecipients(t *testing.T) {
	t.Setenv("SOPS_AGE_KEY", testIdentity)

	// Reference ciphertext, encrypted with a known key set.
	refPlain := []byte("a: 1\nb: secret\n")
	refCiph, err := encrypt.Data(refPlain, "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{ageKeyGroupForCtx(t)},
	})
	if err != nil {
		t.Fatalf("encrypt ref: %v", err)
	}

	// Re-encrypt different plaintext from a reader, same recipients.
	newPlain := []byte("c: different\nd: data\n")
	newCiph, err := encrypt.UsingSameKeysAsFromReader(bytes.NewReader(newPlain), refCiph, "yaml")
	if err != nil {
		t.Fatalf("UsingSameKeysAsFromReader: %v", err)
	}

	recovered, err := decrypt.Data(newCiph, "yaml")
	if err != nil {
		t.Fatalf("decrypt new: %v (key set was not preserved)", err)
	}
	if !bytes.Equal(newPlain, recovered) {
		t.Errorf("round-trip mismatch:\nwant: %q\ngot:  %q", newPlain, recovered)
	}
}

// errReader returns a fixed error on every Read.
type errReader struct{ err error }

func (e *errReader) Read(p []byte) (int, error) { return 0, e.err }

var _ io.Reader = (*errReader)(nil)
