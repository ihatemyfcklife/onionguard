package onionguard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"onionguard/store"
)

func TestAdmission_MaxConcurrentSessionsBound(t *testing.T) {
	mem, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()

	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.MaxConcurrentSessions = 1
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	eng := NewAdmissionEngine(cfg, mem, clock)
	ctx := context.Background()

	s1, err := NewSession(clock.Now(), cfg.MaxRenewals)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := eng.Evaluate(ctx, s1)
	if err != nil || !d1.Allowed {
		t.Fatalf("first session rejected: decision=%+v err=%v", d1, err)
	}

	s2, err := NewSession(clock.Now(), cfg.MaxRenewals)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := eng.Evaluate(ctx, s2)
	if err == nil || !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected capacity rejection, decision=%+v err=%v", d2, err)
	}
}

func TestIdentity_DefaultHTTPIgnoresXAPIKey(t *testing.T) {
	mem, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	validator := TokenValidatorFunc(func(_ context.Context, token string) (string, bool, error) {
		if token == "secret" {
			return "principal", true, nil
		}
		return "", false, nil
	})
	resolver := NewIdentityResolver(DefaultConfig(), mem, RealClock{}, validator, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "secret")
	id, err := resolver.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if id.Kind != IdentityAnonymousNew {
		t.Fatalf("expected X-API-Key to be ignored by default, got %v", id.Kind)
	}
}

func TestEngine_Ping(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	eng, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	ctx := context.Background()
	if err := eng.Ping(ctx); err != nil {
		t.Fatalf("expected ping to succeed, got %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := eng.Ping(ctx); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed after close, got %v", err)
	}
}

type testMetricsSpy struct {
	admitted atomic.Int64
	waitRoom atomic.Int64
	issued   atomic.Int64
	solved   atomic.Int64
	failed   atomic.Int64
	limited  atomic.Int64
}

func (s *testMetricsSpy) OnRequestAdmitted(kind IdentityKind)     { s.admitted.Add(1) }
func (s *testMetricsSpy) OnWaitRoomQueued(waitTime time.Duration) { s.waitRoom.Add(1) }
func (s *testMetricsSpy) OnChallengeIssued()                      { s.issued.Add(1) }
func (s *testMetricsSpy) OnChallengeSolved()                      { s.solved.Add(1) }
func (s *testMetricsSpy) OnChallengeFailed()                      { s.failed.Add(1) }
func (s *testMetricsSpy) OnRateLimited(kind IdentityKind)         { s.limited.Add(1) }

func TestEngine_MetricsObserver(t *testing.T) {
	spy := &testMetricsSpy{}
	clock := NewTestClock(time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Limits = map[RateLimitScope]RateLimitRule{
		ScopeAnonymous: {Rate: 10, Burst: 1, Cost: 1, Window: time.Second},
	}
	eng, err := New(cfg, WithMetricsObserver(spy))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer eng.Close()
	ctx := context.Background()

	// 1. First anonymous request with Captcha enabled -> issues challenge
	req := httptest.NewRequest("GET", "/test", nil)
	dec, err := eng.AuthorizeRequest(ctx, req)
	if err != nil {
		t.Fatalf("AuthorizeRequest failed: %v", err)
	}
	if dec.Admission.State != StateChallengeRequired {
		t.Fatalf("expected StateChallengeRequired, got %v", dec.Admission.State)
	}
	if spy.issued.Load() != 1 {
		t.Fatalf("expected 1 challenge issued event, got %d", spy.issued.Load())
	}

	// 2. Validate Challenge
	sessID := dec.Session.SessionID

	// Failed validation
	if err := eng.ValidateChallenge(ctx, sessID, "wrong_answer"); err == nil {
		t.Fatalf("expected failure for wrong answer")
	}
	if spy.failed.Load() != 1 {
		t.Fatalf("expected 1 challenge failed event, got %d", spy.failed.Load())
	}

	// Deterministic success by setting known answer hash in stored challenge
	data, err := eng.Store().Get(ctx, challengeKey(dec.Challenge.ID))
	if err != nil {
		t.Fatalf("failed to get challenge data: %v", err)
	}
	var stored storedChallenge
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("failed to unmarshal stored challenge: %v", err)
	}
	stored.AnswerHash = sha256Bytes("ABCDE")
	mutated, _ := json.Marshal(stored)
	if err := eng.Store().Set(ctx, challengeKey(dec.Challenge.ID), mutated, time.Minute); err != nil {
		t.Fatalf("failed to save mutated challenge: %v", err)
	}

	// Solved validation
	if err := eng.ValidateChallenge(ctx, sessID, "ABCDE"); err != nil {
		t.Fatalf("expected success for correct answer, got %v", err)
	}
	if spy.solved.Load() != 1 {
		t.Fatalf("expected 1 challenge solved event, got %d", spy.solved.Load())
	}

	// 3. Admitted request
	req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sessID})
	dec2, err := eng.AuthorizeRequest(ctx, req)
	if err != nil {
		t.Fatalf("AuthorizeRequest failed: %v", err)
	}
	if !dec2.Admission.Allowed {
		t.Fatalf("expected admitted, got %v", dec2.Admission.State)
	}
	if spy.admitted.Load() != 1 {
		t.Fatalf("expected 1 admitted event, got %d", spy.admitted.Load())
	}

	// 4. Rate limit rejection (burst = 1 exceeded)
	_, err = eng.AuthorizeRequest(ctx, req)
	if err == nil || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if spy.limited.Load() != 1 {
		t.Fatalf("expected 1 rate limited event, got %d", spy.limited.Load())
	}

	// 5. Test WaitRoom queuing metric
	wrCfg := DefaultConfig()
	wrCfg.Clock = clock
	wrCfg.WaitRoom.Enabled = true
	wrCfg.WaitRoom.WaitTime = 2 * time.Second
	wrCfg.Captcha.Enabled = false
	wrCfg.RateLimit.Enabled = false
	wrEng, err := New(wrCfg, WithMetricsObserver(spy))
	if err != nil {
		t.Fatalf("New for wait room failed: %v", err)
	}
	defer wrEng.Close()

	wrReq := httptest.NewRequest("GET", "/wait", nil)
	wrDec, err := wrEng.AuthorizeRequest(ctx, wrReq)
	if err != nil {
		t.Fatalf("AuthorizeRequest waitroom failed: %v", err)
	}
	if wrDec.Admission.State != StateWaiting {
		t.Fatalf("expected StateWaiting, got %v", wrDec.Admission.State)
	}
	if spy.waitRoom.Load() != 1 {
		t.Fatalf("expected 1 wait room event, got %d", spy.waitRoom.Load())
	}
}

func TestWaitRoom_RenderHTML(t *testing.T) {
	html := RenderWaitRoomHTML(7 * time.Second)
	if html == "" {
		t.Fatal("expected non-empty HTML")
	}
	if !strings.Contains(html, `<meta http-equiv="refresh" content="7">`) {
		t.Fatalf("expected refresh meta tag with 7 seconds, got:\n%s", html)
	}
	if !strings.Contains(html, `default-src 'none'`) {
		t.Fatalf("expected CSP in HTML, got:\n%s", html)
	}
}

func TestEngine_FirstContactRateLimiting(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = true
	// Burst 2 requests allowed for new unauthenticated visitors
	cfg.RateLimit.Limits = map[RateLimitScope]RateLimitRule{
		ScopeAnonymous: {Rate: 1, Burst: 2, Cost: 1, Window: time.Minute},
	}
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ctx := context.Background()

	// Request 1 without cookie: allowed
	req1 := httptest.NewRequest("GET", "/test", nil)
	dec1, err := eng.AuthorizeRequest(ctx, req1)
	if err != nil || !dec1.Admission.Allowed {
		t.Fatalf("first request should be allowed, got: %+v, err: %v", dec1, err)
	}

	// Request 2 without cookie: allowed (burst = 2)
	req2 := httptest.NewRequest("GET", "/test", nil)
	dec2, err := eng.AuthorizeRequest(ctx, req2)
	if err != nil || !dec2.Admission.Allowed {
		t.Fatalf("second request should be allowed, got: %+v, err: %v", dec2, err)
	}

	// Request 3 without cookie: must be rate limited on anon_new:global (burst exceeded)
	req3 := httptest.NewRequest("GET", "/test", nil)
	dec3, err := eng.AuthorizeRequest(ctx, req3)
	if err == nil || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third request without cookie must be rate-limited, got decision: %+v, err: %v", dec3, err)
	}
}

func TestEngine_RevokeAndRotateSession(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ctx := context.Background()

	// 1. Initial request creates admitted session
	req := httptest.NewRequest("GET", "/app", nil)
	dec, err := eng.AuthorizeRequest(ctx, req)
	if err != nil || !dec.Admission.Allowed {
		t.Fatalf("expected admitted session, got: %+v, err: %v", dec, err)
	}
	oldID := dec.Session.SessionID

	// 2. Rotate session via Engine API
	rotated, err := eng.RotateSession(ctx, oldID)
	if err != nil {
		t.Fatalf("RotateSession failed: %v", err)
	}
	if rotated.SessionID == oldID {
		t.Fatal("expected new session ID after rotation")
	}

	// 3. Old session is no longer valid
	reqOld := httptest.NewRequest("GET", "/app", nil)
	reqOld.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: oldID})
	decOld, _ := eng.AuthorizeRequest(ctx, reqOld)
	if decOld.Session.SessionID == oldID {
		t.Fatal("old session ID should not be reused")
	}

	// 4. Revoke session via Engine API
	if err := eng.RevokeSession(ctx, rotated.SessionID); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
	reqRevoked := httptest.NewRequest("GET", "/app", nil)
	reqRevoked.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: rotated.SessionID})
	decRevoked, _ := eng.AuthorizeRequest(ctx, reqRevoked)
	if decRevoked.Admission.State != StateRevoked && decRevoked.Admission.State != StateExpired {
		t.Fatalf("revoked session should be rejected, got: %+v", decRevoked.Admission.State)
	}
}

func TestStore_MemoryNilGuards(t *testing.T) {
	var s *store.MemoryStore
	ctx := context.Background()
	if err := s.Ping(ctx); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.Set(ctx, "k", []byte("v"), time.Second); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.GetDel(ctx, "k"); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.SetNX(ctx, "k", []byte("v"), time.Second); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.CompareAndDelete(ctx, "k", []byte("v")); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.CompareAndTouch(ctx, "k", []byte("v"), time.Second); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.Touch(ctx, "k", time.Second); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, err := s.IncrementWithTTL(ctx, "k", 1, time.Second); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if _, _, err := s.ConsumeToken(ctx, "k", 1, 1, 1, time.Second, time.Now()); !errors.Is(err, store.ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed, got %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("expected nil from nil Close(), got %v", err)
	}
}

func TestStore_RedisURLParsing(t *testing.T) {
	r, err := store.NewRedisStore(store.RedisConfig{
		Addr: "redis://:secret@127.0.0.1:6379/2",
	})
	if err != nil {
		t.Fatalf("expected NewRedisStore to parse redis:// URL, got: %v", err)
	}
	defer r.Close()
}

func TestEngine_NilGuards(t *testing.T) {
	var nilEng *Engine
	if cfg := nilEng.Config(); cfg.MaxBodyBytes != 0 {
		t.Errorf("expected empty config for nil engine, got %+v", cfg)
	}
	if s := nilEng.Store(); s != nil {
		t.Errorf("expected nil store for nil engine, got %v", s)
	}
	if m := nilEng.Metrics(); m != nil {
		t.Errorf("expected nil metrics for nil engine, got %v", m)
	}
	ctx := context.Background()
	if _, err := nilEng.IssueChallenge(ctx, "session-id"); !errors.Is(err, ErrEngineNotInitialized) {
		t.Errorf("expected ErrEngineNotInitialized, got %v", err)
	}
	if err := nilEng.ValidateChallenge(ctx, "session-id", "ANS"); !errors.Is(err, ErrEngineNotInitialized) {
		t.Errorf("expected ErrEngineNotInitialized, got %v", err)
	}
	if _, err := nilEng.GetChallenge(ctx, "session-id"); !errors.Is(err, ErrEngineNotInitialized) {
		t.Errorf("expected ErrEngineNotInitialized, got %v", err)
	}
	if _, err := nilEng.ResolveIdentity(nil); !errors.Is(err, ErrEngineNotInitialized) {
		t.Errorf("expected ErrEngineNotInitialized, got %v", err)
	}
	if _, err := nilEng.EvaluateSession(ctx, nil); !errors.Is(err, ErrEngineNotInitialized) {
		t.Errorf("expected ErrEngineNotInitialized, got %v", err)
	}
	if err := nilEng.RevokeSession(ctx, "session-id"); !errors.Is(err, ErrEngineNotInitialized) {
		t.Errorf("expected ErrEngineNotInitialized, got %v", err)
	}
	if _, err := nilEng.RotateSession(ctx, "session-id"); !errors.Is(err, ErrEngineNotInitialized) {
		t.Errorf("expected ErrEngineNotInitialized, got %v", err)
	}
}

func TestClientSafeError_StoreClosed(t *testing.T) {
	adm := ClientSafeError(store.ErrStoreClosed)
	if adm.StatusCode != 503 {
		t.Fatalf("expected 503 for ErrStoreClosed, got %d", adm.StatusCode)
	}
	if adm.Code != "SERVICE_UNAVAILABLE" {
		t.Fatalf("expected SERVICE_UNAVAILABLE, got %s", adm.Code)
	}
}

func TestRevokeSessionWithClock_Deterministic(t *testing.T) {
	mem, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()

	clock := NewTestClock(time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC))
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(time.Hour)
	ctx := context.Background()
	if err := SaveSession(ctx, mem, sess, time.Hour); err != nil {
		t.Fatal(err)
	}

	clock.Advance(10 * time.Minute)
	if err := RevokeSessionWithClock(ctx, mem, sess.SessionID, 5*time.Minute, clock); err != nil {
		t.Fatalf("RevokeSessionWithClock failed: %v", err)
	}

	loaded, err := GetSession(ctx, mem, sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != StateRevoked {
		t.Fatalf("expected StateRevoked, got %s", loaded.State)
	}
	if !loaded.LastSeenAt.Equal(clock.Now()) {
		t.Fatalf("expected LastSeenAt to match clock %v, got %v", clock.Now(), loaded.LastSeenAt)
	}
}
