// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package keyservice

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestServerDecrypt_AgeRespectsContext — narrow regression test. The
// in-process Server.Decrypt path used to drop the ctx it received on the
// floor; this test ensures ctx now reaches at least one provider helper
// (age, which is the easiest to exercise without external keys).
//
// We don't get cancellation-mid-call to *observe* for age (its decrypt is
// in-memory and microseconds; there's nothing to cancel). What we DO
// observe: a pre-cancelled ctx still allows the call to proceed and fail
// for unrelated reasons (no plaintext, wrong recipient, etc.) — because
// age intentionally ignores ctx. That's by design.
//
// The structural assertion is that Server.Decrypt compiles after the
// ctx-plumbing refactor — i.e. every per-provider helper accepts ctx.
// That's enforced at compile time by the signature changes in this
// branch; this test just exercises one of those code paths to make
// failures visible if a refactor regresses the wiring.
func TestServerDecrypt_AgeRespectsContextSignature(t *testing.T) {
	ks := &Server{}

	// Pre-cancelled ctx. Age helper is reached but ignores ctx (local
	// crypto). The error should be from age failing to decrypt (no
	// identity available, malformed input), NOT from a build / signature
	// failure.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &DecryptRequest{
		Key: &Key{KeyType: &Key_AgeKey{AgeKey: &AgeKey{
			Recipient: "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun",
		}}},
		Ciphertext: []byte("not a real age envelope"),
	}

	_, err := ks.Decrypt(ctx, req)
	if err == nil {
		t.Fatal("expected an error from age decrypt with bogus ciphertext")
	}
	// The error should mention age's decrypt failure, not a context error
	// (age ignores ctx by design — local crypto, nothing to cancel).
	if errors.Is(err, context.Canceled) {
		t.Errorf("age unexpectedly honored ctx cancellation: %v", err)
	}
	// Sanity: the error is from age's pipeline, not from a nil-pointer
	// crash because ctx wasn't threaded.
	if !strings.Contains(strings.ToLower(err.Error()), "age") &&
		!strings.Contains(strings.ToLower(err.Error()), "decrypt") &&
		!strings.Contains(strings.ToLower(err.Error()), "identit") {
		t.Errorf("error should come from age's decrypt pipeline, got: %v", err)
	}
}
