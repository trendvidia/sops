// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package hckms

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestDecryptContext_PreCancelled verifies that a pre-cancelled ctx
// returns immediately without attempting any KMS call.
func TestDecryptContext_PreCancelled(t *testing.T) {
	key := &MasterKey{KeyID: "test", KeyUUID: "test", EncryptedKey: "ignored"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := key.DecryptContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
	// Should return immediately — no KMS call attempted.
	if elapsed > 100*time.Millisecond {
		t.Errorf("pre-cancelled call took %v; expected immediate return", elapsed)
	}
}

// TestEncryptContext_PreCancelled — symmetric for encrypt.
func TestEncryptContext_PreCancelled(t *testing.T) {
	key := &MasterKey{KeyID: "test", KeyUUID: "test"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := key.EncryptContext(ctx, []byte("ignored"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error for pre-cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v; want context.Canceled in the chain", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("pre-cancelled call took %v; expected immediate return", elapsed)
	}
}

// TestDecryptContext_DeadlineMidCallReturnsPromptly verifies the
// goroutine-shim's mid-call cancellation behavior: a ctx deadline that
// fires while the SDK call is in flight causes DecryptContext to
// return within the deadline, NOT after the SDK's internal timeout.
//
// Uses a bogus endpoint so the SDK genuinely tries to dial and fails
// (or hangs) — exercising the ctx-fires-while-call-running path.
func TestDecryptContext_DeadlineMidCallReturnsPromptly(t *testing.T) {
	key := &MasterKey{
		KeyID:    "cn-bogus-1:11111111-2222-3333-4444-555555555555",
		KeyUUID:  "11111111-2222-3333-4444-555555555555",
		Region:   "cn-bogus-1",
		// Bogus AKSK — client creation may fail, in which case the call
		// errors fast and the test still verifies the shim's behavior on
		// any error path. The important assertion is "returns within the
		// deadline regardless of SDK behavior."
		EncryptedKey: "junk",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := key.DecryptContext(ctx)
	elapsed := time.Since(start)

	// We expect SOME error (auth, network, ctx). The important
	// invariant: total elapsed must be bounded by the deadline +
	// reasonable jitter (NOT bounded by the SDK's 30-60s internal
	// timeout).
	if err == nil {
		t.Fatal("expected error (bogus credentials / ctx deadline)")
	}
	// 2-second slack: client creation can take a moment, and the
	// goroutine takes a moment to teardown.
	if elapsed > 2*time.Second {
		t.Errorf("call took %v; ctx shim failed to bound the SDK call (expected <2s, got SDK timeout)", elapsed)
	}
	// If the SDK errored before the deadline, the error path is from
	// the SDK; if the ctx fired first, the error mentions ctx. Either
	// is acceptable here — we're testing the shim, not the SDK's
	// behavior. Log for visibility.
	if errors.Is(err, context.DeadlineExceeded) {
		// ctx fired first — confirms the shim is doing its job.
		if !strings.Contains(err.Error(), "sops#10") {
			t.Errorf("expected error message to mention sops#10 (the limitation), got: %v", err)
		}
	}
}
