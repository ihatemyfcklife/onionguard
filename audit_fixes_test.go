package onionguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"onionguard/store"
)

func TestAudit_SessionCookie_RevokedOrExpired_ClearsCookie(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.Clock = clock
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer eng.Close()

	// 1. Revoked session
	sessRevoked, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sessRevoked.State = StateRevoked
	cRevoked := eng.SessionCookie(sessRevoked)
	if cRevoked == nil {
		t.Fatal("expected cookie for revoked session")
	}
	if cRevoked.MaxAge != -1 {
		t.Errorf("expected MaxAge -1 for revoked session cookie, got %d", cRevoked.MaxAge)
	}
	if cRevoked.Value != "" {
		t.Errorf("expected empty value for revoked session cookie, got %q", cRevoked.Value)
	}
	if !cRevoked.Expires.Before(clock.Now()) {
		t.Errorf("expected past Expires for revoked cookie, got %v", cRevoked.Expires)
	}

	// 2. Expired session
	sessExpired, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sessExpired.State = StateExpired
	sessExpired.ExpiresAt = clock.Now().Add(-1 * time.Minute)
	cExpired := eng.SessionCookie(sessExpired)
	if cExpired == nil {
		t.Fatal("expected cookie for expired session")
	}
	if cExpired.MaxAge != -1 {
		t.Errorf("expected MaxAge -1 for expired session cookie, got %d", cExpired.MaxAge)
	}
	if cExpired.Value != "" {
		t.Errorf("expected empty value for expired session cookie, got %q", cExpired.Value)
	}
}

func TestAudit_Challenge_MaxAttemptsExceeded_ExpelsToWaiting(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 10 * time.Second
	cfg.Captcha.Enabled = true
	cfg.Captcha.MaxAttempts = 2

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer eng.Close()
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = StateChallengeRequired
	if err := SaveSession(ctx, eng.Store(), sess, time.Hour); err != nil {
		t.Fatal(err)
	}

	ch, err := eng.IssueChallenge(ctx, sess.SessionID)
	if err != nil || ch == nil {
		t.Fatalf("IssueChallenge failed: %v", err)
	}

	// Attempt 1: wrong answer (valid length 5)
	err = eng.ValidateChallenge(ctx, sess.SessionID, "WRO01")
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("expected ErrChallengeFailed on attempt 1, got %v", err)
	}

	// Attempt 2: wrong answer (triggers max attempts)
	err = eng.ValidateChallenge(ctx, sess.SessionID, "WRO02")
	if !errors.Is(err, ErrMaxAttemptsExceeded) {
		t.Fatalf("expected ErrMaxAttemptsExceeded on attempt 2, got %v", err)
	}

	// Verify session in store was expelled to StateWaiting and ChallengeID cleared
	fresh, err := GetSession(ctx, eng.Store(), sess.SessionID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if fresh.State != StateWaiting {
		t.Errorf("expected session to be expelled to StateWaiting, got %s", fresh.State)
	}
	if fresh.ChallengeID != "" {
		t.Errorf("expected ChallengeID to be cleared, got %q", fresh.ChallengeID)
	}
}

func TestAudit_ClientSafeError_InvalidTransition(t *testing.T) {
	adm := ClientSafeError(ErrInvalidTransition)
	if adm == nil {
		t.Fatal("expected non-nil AdmissionError")
	}
	if adm.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", adm.StatusCode)
	}
	if adm.Code != "INVALID_TRANSITION" {
		t.Errorf("expected code INVALID_TRANSITION, got %s", adm.Code)
	}
}

type countingStore struct {
	store.Store
	getCount int
}

func (c *countingStore) Get(ctx context.Context, key string) ([]byte, error) {
	c.getCount++
	return c.Store.Get(ctx, key)
}

func TestAudit_Priority1_AdmittedSession_SingleStoreLookup(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	cs := &countingStore{Store: memStore}

	cfg := DefaultConfig()
	cfg.Clock = clock
	cfg.Store = cs

	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer eng.Close()
	ctx := context.Background()

	// Create an admitted session in store
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = StateAdmitted
	if err := SaveSession(ctx, eng.Store(), sess, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Build HTTP request presenting the admitted session cookie
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  cfg.SessionCookieName,
		Value: sess.SessionID,
	})

	// Reset counter before AuthorizeRequest
	cs.getCount = 0

	dec, err := eng.AuthorizeRequest(ctx, req)
	if err != nil {
		t.Fatalf("AuthorizeRequest failed: %v", err)
	}
	if !dec.Admission.Allowed {
		t.Fatalf("expected admitted request, got allowed=false (state=%s)", dec.Admission.State)
	}

	// Verify that GetSession was invoked EXACTLY ONCE (in identity resolver),
	// rather than 3 times (identity resolver + authorizeRequest + Evaluate).
	if cs.getCount != 1 {
		t.Errorf("expected exactly 1 store.Get call on admitted request, got %d", cs.getCount)
	}
}
