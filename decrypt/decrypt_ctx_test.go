// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package decrypt

import (
	"context"
	"errors"
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/encrypt"
)

func TestDataWithContext_PreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DataWithContext(ctx, []byte("ignored"), "yaml")
	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

func TestDataWithFormatContext_PreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DataWithFormatContext(ctx, []byte("ignored"), formats.Yaml)
	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

func TestFileWithContext_PreCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := FileWithContext(ctx, "/dev/null", "yaml")
	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

// TestDataWithContext_DelegatesToData proves the ctx variant produces
// the same result as Data when the ctx is alive. Uses an
// intentionally-malformed input so we can compare the error from both
// paths instead of needing real ciphertext fixtures.
func TestDataWithContext_DelegatesToData(t *testing.T) {
	in := []byte(`{"sops": {"version": "3.13.0"}}`) // syntactically valid YAML/JSON but no encryption metadata
	_, errCtx := DataWithContext(context.Background(), in, "json")
	_, errPlain := Data(in, "json")
	if (errCtx == nil) != (errPlain == nil) {
		t.Fatalf("ctx and non-ctx variants disagree on success: ctx=%v plain=%v", errCtx, errPlain)
	}
	if errCtx != nil && errCtx.Error() != errPlain.Error() {
		t.Errorf("ctx/non-ctx error texts differ:\n  ctx:   %v\n  plain: %v", errCtx, errPlain)
	}
}

// TestDataWithContext_HappyPathAge proves the ctx-wired decrypt path
// round-trips real age-encrypted ciphertext successfully — i.e. the
// new tree.Metadata.GetDataKeyCtx call hasn't broken the success branch.
func TestDataWithContext_HappyPathAge(t *testing.T) {
	const (
		recipient = "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"
		identity  = "AGE-SECRET-KEY-1G0Q5K9TV4REQ3ZSQRMTMG8NSWQGYT0T7TZ33RAZEE0GZYVZN0APSU24RK7"
	)
	t.Setenv("SOPS_AGE_KEY", identity)

	mk, err := age.MasterKeyFromRecipient(recipient)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	plaintext := []byte("payload: ok\n")
	ciphertext, err := encrypt.Data(plaintext, "yaml", encrypt.Options{
		KeyGroups: []sops.KeyGroup{{mk}},
	})
	if err != nil {
		t.Fatalf("setup encrypt: %v", err)
	}

	got, err := DataWithContext(context.Background(), ciphertext, "yaml")
	if err != nil {
		t.Fatalf("DataWithContext: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext mismatch:\nwant: %q\ngot:  %q", plaintext, got)
	}
}
