// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package sops

import (
	"context"
	"errors"
	"testing"

	"github.com/trendvidia/sops/v3/keyservice"
)

// TestGetDataKeyCtx_PreCancelled — a cancelled ctx returns fast without
// touching any keyservice.
func TestGetDataKeyCtx_PreCancelled(t *testing.T) {
	m := &Metadata{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := m.GetDataKeyCtx(ctx)
	if err == nil {
		t.Fatal("expected error for pre-cancelled context; got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

// TestGetDataKeyCtxWithKeyServices_PreCancelled — same on the with-services
// entry point.
func TestGetDataKeyCtxWithKeyServices_PreCancelled(t *testing.T) {
	m := &Metadata{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := m.GetDataKeyCtxWithKeyServices(ctx, []keyservice.KeyServiceClient{
		keyservice.NewLocalClient(),
	}, nil)
	if err == nil {
		t.Fatal("expected error for pre-cancelled context; got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
}

// TestGetDataKey_DelegatesViaBackground — backward-compat smoke. The
// non-ctx GetDataKey is now a thin wrapper around GetDataKeyCtx(Background());
// behavior on an empty Metadata should match either path.
func TestGetDataKey_DelegatesViaBackground(t *testing.T) {
	m1 := &Metadata{}
	m2 := &Metadata{}
	_, errLegacy := m1.GetDataKey()
	_, errCtx := m2.GetDataKeyCtx(context.Background())
	if (errLegacy == nil) != (errCtx == nil) {
		t.Fatalf("legacy and ctx variants disagree on empty Metadata: legacy=%v ctx=%v",
			errLegacy, errCtx)
	}
}
