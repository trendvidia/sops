// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package decrypt

import (
	"context"
	"errors"
	"testing"

	"github.com/getsops/sops/v3/cmd/sops/formats"
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
