package onionguard

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

// TestRedisOutagePolicies exercises the real go-redis client against a refused
// TCP endpoint. It documents the deliberate boundary: only rate limiting can
// be configured fail-open; session, admission, and challenge storage fail closed.
func TestRedisOutagePolicies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s, err := store.NewRedisStore(store.RedisConfig{Addr: "127.0.0.1:6399", DialTimeout: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	cfg := DefaultConfig()
	cfg.Store = s
	cfg.StoreConfig.RedisFailClosed = true
	rl := NewRateLimiter(cfg, s, cfg.Clock)
	_, err = rl.Allow(ctx, ClientIdentity{Kind: IdentityAnonymous, SessionID: "outage"}, "GET:/", 0)
	if !errors.Is(err, store.ErrStoreUnavailable) {
		t.Fatalf("fail-closed limiter error = %v, want store unavailable", err)
	}

	cfg.StoreConfig.RedisFailClosed = false
	rl = NewRateLimiter(cfg, s, cfg.Clock)
	result, err := rl.Allow(ctx, ClientIdentity{Kind: IdentityAnonymous, SessionID: "outage"}, "GET:/", 0)
	if err != nil || !result.Allowed {
		t.Fatalf("fail-open limiter = %+v, %v", result, err)
	}

	cfg.RateLimit.Enabled = false
	engine, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	_, err = engine.AuthorizeRequest(ctx, httptest.NewRequest("GET", "http://example.test/", nil))
	if !errors.Is(err, store.ErrStoreUnavailable) {
		t.Fatalf("session/admission outage error = %v, want store unavailable", err)
	}

	id, err := GenerateSessionID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.IssueChallenge(ctx, id)
	if !errors.Is(err, store.ErrStoreUnavailable) {
		t.Fatalf("challenge issue outage error = %v, want store unavailable", err)
	}
	if err := engine.ValidateChallenge(ctx, id, "ABCDE"); !errors.Is(err, store.ErrStoreUnavailable) {
		t.Fatalf("challenge validation outage error = %v, want store unavailable", err)
	}
}
