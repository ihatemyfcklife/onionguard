package onionguard

import (
	"context"
	"errors"
	"testing"
	"time"

	"onionguard/store"
)

func TestRateLimiterTokenBucketAndTTL(t *testing.T) {
	s, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer s.Close()
	clock := NewTestClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.RateLimit.Limits[ScopeAnonymous] = RateLimitRule{Rate: 1, Burst: 2, Cost: 1, Window: 10 * time.Second}
	rl := NewRateLimiter(cfg, s, clock)
	id := ClientIdentity{Kind: IdentityAnonymousNew, SessionID: "x"}
	if _, err := rl.Allow(context.Background(), id, "GET:/", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := rl.Allow(context.Background(), id, "GET:/", 0); err != nil {
		t.Fatal(err)
	}
	res, err := rl.Allow(context.Background(), id, "GET:/", 0)
	if !errors.Is(err, ErrRateLimited) || res.Allowed {
		t.Fatalf("expected rate limited, res=%+v err=%v", res, err)
	}
	clock.Advance(time.Second)
	if _, err := rl.Allow(context.Background(), id, "GET:/", 0); err != nil {
		t.Fatal(err)
	}
}
