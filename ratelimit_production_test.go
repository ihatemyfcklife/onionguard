package onionguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

// TestRateLimiter_GlobalIdentityEnforcementAcrossPaths verifies that
// rate limiting binds to the client's identity rather than fragmenting per-URL path.
func TestRateLimiter_GlobalIdentityEnforcementAcrossPaths(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.Clock = clock
	// Anonymous rule: 2 requests burst, rate 1/s
	cfg.RateLimit.Limits[ScopeAnonymous] = RateLimitRule{
		Rate:   1,
		Burst:  2,
		Cost:   1,
		Window: 1 * time.Minute,
	}

	limiter := NewRateLimiter(cfg, memStore, clock)
	ctx := context.Background()

	sessID := "test-session-1234567890abcdef1234567890abcd"
	id := ClientIdentity{
		Kind:      IdentityAnonymous,
		SessionID: sessID,
	}

	// Request 1 to /path-alpha
	res1, err := limiter.Allow(ctx, id, "GET:/path-alpha", 0)
	if err != nil || !res1.Allowed {
		t.Fatalf("request 1 should be allowed, got res=%+v err=%v", res1, err)
	}

	// Request 2 to /path-beta (different path!)
	res2, err := limiter.Allow(ctx, id, "GET:/path-beta", 0)
	if err != nil || !res2.Allowed {
		t.Fatalf("request 2 should be allowed, got res=%+v err=%v", res2, err)
	}

	// Request 3 to /path-gamma (burst of 2 is now exhausted across paths!)
	res3, err := limiter.Allow(ctx, id, "GET:/path-gamma", 0)
	if !errors.Is(err, ErrRateLimited) || res3.Allowed {
		t.Fatalf("request 3 across paths should be rate limited, got res=%+v err=%v", res3, err)
	}

	// After 1 second, tokens replenish
	clock.Advance(1 * time.Second)
	res4, err := limiter.Allow(ctx, id, "GET:/path-delta", 0)
	if err != nil || !res4.Allowed {
		t.Fatalf("request 4 should be allowed after token replenishment, got res=%+v err=%v", res4, err)
	}
}

// TestRateLimiter_FirstContactGlobalPoolBindsAcrossPaths verifies that unassigned visitors
// share the global first-contact pool across different paths, preventing DoS bypass by path rotation.
func TestRateLimiter_FirstContactGlobalPoolBindsAcrossPaths(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.Clock = clock
	cfg.RateLimit.Limits[ScopeFirstContact] = RateLimitRule{
		Rate:   1,
		Burst:  2,
		Cost:   1,
		Window: 1 * time.Minute,
	}

	limiter := NewRateLimiter(cfg, memStore, clock)
	ctx := context.Background()

	// Two unassigned visitors hitting different paths
	visitor1 := ClientIdentity{Kind: IdentityAnonymousNew, SessionID: ""}
	visitor2 := ClientIdentity{Kind: IdentityAnonymousNew, SessionID: ""}

	res1, err := limiter.Allow(ctx, visitor1, "GET:/random-1", 0)
	if err != nil || !res1.Allowed {
		t.Fatalf("visitor 1 should be allowed, got res=%+v err=%v", res1, err)
	}

	res2, err := limiter.Allow(ctx, visitor2, "GET:/random-2", 0)
	if err != nil || !res2.Allowed {
		t.Fatalf("visitor 2 should be allowed, got res=%+v err=%v", res2, err)
	}

	// Third visitor hitting yet another random path must be rate limited
	visitor3 := ClientIdentity{Kind: IdentityAnonymousNew, SessionID: ""}
	res3, err := limiter.Allow(ctx, visitor3, "GET:/random-3", 0)
	if !errors.Is(err, ErrRateLimited) || res3.Allowed {
		t.Fatalf("visitor 3 should be rate limited under ScopeFirstContact, got res=%+v err=%v", res3, err)
	}
}

// TestRateLimiter_EngineIntegration_CrossPathQuota verifies AuthorizeRequest enforces
// total quota across multiple HTTP requests to different URLs.
func TestRateLimiter_EngineIntegration_CrossPathQuota(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Limits[ScopeAnonymous] = RateLimitRule{
		Rate:   1,
		Burst:  2,
		Cost:   1,
		Window: 1 * time.Minute,
	}

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer eng.Close()
	ctx := context.Background()

	// Create admitted session
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	if err := SaveSession(ctx, eng.Store(), sess, 1*time.Hour); err != nil {
		t.Fatal(err)
	}

	cookie := &http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID}

	req1 := httptest.NewRequest("GET", "/article/1", nil)
	req1.AddCookie(cookie)
	dec1, err := eng.AuthorizeRequest(ctx, req1)
	if err != nil || !dec1.Admission.Allowed {
		t.Fatalf("req 1 should be allowed, got dec=%+v err=%v", dec1, err)
	}

	req2 := httptest.NewRequest("GET", "/article/2", nil)
	req2.AddCookie(cookie)
	dec2, err := eng.AuthorizeRequest(ctx, req2)
	if err != nil || !dec2.Admission.Allowed {
		t.Fatalf("req 2 should be allowed, got dec=%+v err=%v", dec2, err)
	}

	// Request 3 to a 3rd path must be rate limited
	req3 := httptest.NewRequest("GET", "/article/3", nil)
	req3.AddCookie(cookie)
	_, err = eng.AuthorizeRequest(ctx, req3)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("req 3 should be rate limited across paths, got err=%v", err)
	}
}
