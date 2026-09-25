package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	og "onionguard"
)

func TestAudit_Middleware_ChallengeAlreadyAdmitted_Redirects(t *testing.T) {
	clock := og.NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := og.DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true

	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ctx := context.Background()

	sess, err := og.NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = og.StateAdmitted
	sess.ExpiresAt = clock.Now().Add(time.Hour)
	if err := og.SaveSession(ctx, eng.Store(), sess, time.Hour); err != nil {
		t.Fatal(err)
	}

	handler := Middleware(eng)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 1. HTML request to /onionguard/challenge from admitted client -> Redirect 302
	reqHTML := httptest.NewRequest(http.MethodGet, "/onionguard/challenge", nil)
	reqHTML.Header.Set("Accept", "text/html")
	reqHTML.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})
	recHTML := httptest.NewRecorder()
	handler.ServeHTTP(recHTML, reqHTML)

	if recHTML.Code != http.StatusFound {
		t.Errorf("expected 302 redirect for admitted HTML client, got %d", recHTML.Code)
	}
	if loc := recHTML.Header().Get("Location"); loc != "/" {
		t.Errorf("expected Location '/', got %q", loc)
	}

	// 2. JSON request to /onionguard/challenge from admitted client -> 200 OK
	reqJSON := httptest.NewRequest(http.MethodGet, "/onionguard/challenge", nil)
	reqJSON.Header.Set("Accept", "application/json")
	reqJSON.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})
	recJSON := httptest.NewRecorder()
	handler.ServeHTTP(recJSON, reqJSON)

	if recJSON.Code != http.StatusOK {
		t.Errorf("expected 200 OK for admitted JSON client, got %d", recJSON.Code)
	}
}

func TestAudit_Middleware_ChallengeMaxAttempts_ExpelsToWaitRoom(t *testing.T) {
	clock := og.NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := og.DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = true
	cfg.Captcha.MaxAttempts = 1 // 1 attempt then expelled

	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	ctx := context.Background()

	sess, err := og.NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = og.StateChallengeRequired
	if err := og.SaveSession(ctx, eng.Store(), sess, time.Hour); err != nil {
		t.Fatal(err)
	}

	// Issue the initial challenge
	_, err = eng.IssueChallenge(ctx, sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}

	handler := Middleware(eng)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// POST wrong answer to exceed max attempts
	postReq := httptest.NewRequest(http.MethodPost, "/onionguard/challenge", strings.NewReader("answer=WRONG"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Accept", "text/html")
	postReq.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, postReq)

	// Must return HTTP 429 Wait Room instead of issuing a new challenge
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 Too Many Requests after max attempts, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Please wait") {
		t.Errorf("expected wait room HTML body, got: %s", rec.Body.String())
	}
}
