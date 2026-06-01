// Copyright 2026 TrendVidia LLC (fork-only addition; under sops's MPL-2.0).
// SPDX-License-Identifier: MPL-2.0

package sops

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trendvidia/sops/v3/age"
	"github.com/trendvidia/sops/v3/keyservice"
	"google.golang.org/grpc"
)

// blockingKS is a fake [keyservice.KeyServiceClient] whose Decrypt/Encrypt
// block until the supplied ctx is cancelled, then return ctx.Err(). It
// observes mid-call cancellation: if the caller's ctx is being threaded
// through, a deadlined ctx aborts the call within the deadline; if it
// isn't, the fake's safety timeout (fakeTimeout) fires and the test
// fails with a clear "ctx was not honored" message instead of hanging.
type blockingKS struct {
	called int32 // atomic; set non-zero once Decrypt/Encrypt is entered
}

const fakeTimeout = 2 * time.Second

func (b *blockingKS) Decrypt(ctx context.Context, req *keyservice.DecryptRequest, _ ...grpc.CallOption) (*keyservice.DecryptResponse, error) {
	atomic.StoreInt32(&b.called, 1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(fakeTimeout):
		return nil, errors.New("blockingKS: ctx was not honored — fake timed out before cancellation")
	}
}

func (b *blockingKS) Encrypt(ctx context.Context, req *keyservice.EncryptRequest, _ ...grpc.CallOption) (*keyservice.EncryptResponse, error) {
	atomic.StoreInt32(&b.called, 1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(fakeTimeout):
		return nil, errors.New("blockingKS: ctx was not honored — fake timed out before cancellation")
	}
}

const (
	// Stable test recipient from age/keysource_test.go.
	testAgeRecipient = "age1lzd99uklcjnc0e7d860axevet2cz99ce9pq6tzuzd05l5nr28ams36nvun"
)

// TestGetDataKeyCtx_CancelsMidCall proves that a deadlined ctx aborts an
// in-flight keyservice.Decrypt call mid-flight — i.e. ctx is threaded
// all the way to the keyservice and honored there, not just checked at
// entry. Uses a fake keyservice that blocks on ctx.Done().
func TestGetDataKeyCtx_CancelsMidCall(t *testing.T) {
	mk, err := age.MasterKeyFromRecipient(testAgeRecipient)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	mk.EncryptedKey = "ignored"
	m := &Metadata{KeyGroups: []KeyGroup{{mk}}}

	fake := &blockingKS{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = m.GetDataKeyCtxWithKeyServices(ctx, []keyservice.KeyServiceClient{fake}, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error from cancelled ctx; got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err chain should include context.DeadlineExceeded; got: %v", err)
	}
	if atomic.LoadInt32(&fake.called) == 0 {
		t.Error("fake keyservice's Decrypt was never reached — ctx was honored too early, before threading test")
	}
	// Slack: 100ms deadline + ~50ms for goroutine setup / Shamir math.
	if elapsed > 500*time.Millisecond {
		t.Errorf("call took %v; expected ~100ms (ctx deadline). suggests ctx not threaded into svc.Decrypt", elapsed)
	}
}

// TestUpdateMasterKeysCtx_CancelsMidCall — symmetric test for the encrypt
// path. A deadlined ctx aborts an in-flight keyservice.Encrypt call.
func TestUpdateMasterKeysCtx_CancelsMidCall(t *testing.T) {
	mk, err := age.MasterKeyFromRecipient(testAgeRecipient)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	m := &Metadata{KeyGroups: []KeyGroup{{mk}}}

	fake := &blockingKS{}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	errs := m.UpdateMasterKeysCtxWithKeyServices(ctx, []byte("data-key"), []keyservice.KeyServiceClient{fake})
	elapsed := time.Since(start)

	if len(errs) == 0 {
		t.Fatal("expected error from cancelled ctx; got none")
	}
	var found bool
	for _, e := range errs {
		if errors.Is(e, context.DeadlineExceeded) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("errs chain should include context.DeadlineExceeded; got: %v", errs)
	}
	if atomic.LoadInt32(&fake.called) == 0 {
		t.Error("fake keyservice's Encrypt was never reached")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("call took %v; expected ~100ms. suggests ctx not threaded into svc.Encrypt", elapsed)
	}
}

// TestGetDataKeyCtx_NotCancelledCompletes — sanity check: when ctx is
// alive, the call proceeds and the fake's safety timeout fires (because
// ctx never cancels). This verifies the test infrastructure: ctx not
// being threaded would also produce this outcome, so this test is
// asymmetric with the cancellation tests above. Useful as documentation
// rather than as a discriminator.
func TestGetDataKeyCtx_NotCancelledHitsFakeTimeout(t *testing.T) {
	mk, err := age.MasterKeyFromRecipient(testAgeRecipient)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	mk.EncryptedKey = "ignored"
	m := &Metadata{KeyGroups: []KeyGroup{{mk}}}

	fake := &blockingKS{}
	// Background ctx — won't cancel. Fake's safety timeout (fakeTimeout)
	// is what eventually unsticks the call.
	_, err = m.GetDataKeyCtxWithKeyServices(context.Background(), []keyservice.KeyServiceClient{fake}, nil)
	if err == nil {
		t.Fatal("expected error from fake's safety timeout")
	}
	// The error must come from the fake (no ctx error in chain), proving
	// the call WAS made and returned the fake's "not honored" error.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Errorf("err should not be a ctx error when ctx is Background; got: %v", err)
	}
}
