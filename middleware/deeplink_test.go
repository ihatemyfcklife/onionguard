package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	og "onionguard"
)

// TestDeepLink_PreservesTargetURL_FullFlow verifies that an unadmitted client requesting a deep link
// (/protected/doc?section=3) preserves that target URL across the CAPTCHA form submission and verification.
func TestDeepLink_PreservesTargetURL_FullFlow(t *testing.T) {
	clock := og.NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := og.DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true
	cfg.Captcha.Alphabet = "AAAAAAAAAA" // Guaranteed answer "AAAAA"
	cfg.Captcha.Length = 5

	engine, err := og.New(cfg)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	sess, err := og.NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = og.StateChallengeRequired
	if err := og.SaveSession(ctx, engine.Store(), sess, time.Hour); err != nil {
		t.Fatal(err)
	}

	handler := Middleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("admitted backend: " + r.URL.Path))
	}))

	// Step 1: Deep link request to /protected/doc?section=3
	deepURL := "/protected/doc?section=3"
	req1 := httptest.NewRequest("GET", deepURL, nil)
	req1.Header.Set("Accept", "text/html")
	req1.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr1.Code)
	}
	if !strings.Contains(rr1.Body.String(), `<input type="hidden" name="target" value="/protected/doc?section=3">`) {
		t.Fatalf("target was not embedded in CAPTCHA form: %s", rr1.Body.String())
	}

	// Step 2: Submit POST /onionguard/challenge with answer="AAAAA" and target="/protected/doc?section=3"
	form := url.Values{}
	form.Set("answer", "AAAAA")
	form.Set("target", deepURL)
	req2 := httptest.NewRequest("POST", "/onionguard/challenge", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Accept", "text/html")
	req2.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK verification, got %d: %s", rr2.Code, rr2.Body.String())
	}
	expectedRefresh := `<meta http-equiv="refresh" content="1;url=/protected/doc?section=3">`
	if !strings.Contains(rr2.Body.String(), expectedRefresh) {
		t.Fatalf("expected refresh to target deep URL, got:\n%s", rr2.Body.String())
	}

	// Step 3: Now that session is admitted, verify GET /onionguard/challenge redirects to target
	req3 := httptest.NewRequest("GET", "/onionguard/challenge?target=/protected/doc?section=3", nil)
	req3.Header.Set("Accept", "text/html")
	req3.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})
	rr3 := httptest.NewRecorder()
	handler.ServeHTTP(rr3, req3)

	if rr3.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect for already admitted session, got %d", rr3.Code)
	}
	if loc := rr3.Header().Get("Location"); loc != deepURL {
		t.Fatalf("expected redirect Location %q, got %q", deepURL, loc)
	}
}

// TestDeepLink_Sanitization tests that malicious target URLs are sanitized to "/"
func TestDeepLink_Sanitization(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"", "/"},
		{"/", "/"},
		{"/valid/path", "/valid/path"},
		{"/valid/path?query=1&b=2", "/valid/path?query=1&b=2"},
		{"//evil.com/phish", "/"},
		{"///evil.com", "/"},
		{"https://evil.com", "/"},
		{"http://evil.com/steal", "/"},
		{"javascript:alert(1)", "/"},
		{"\\evil.com", "/"},
		{"/evil.com\\foo", "/"},
		{"/path\r\nInjected-Header: evil", "/"},
		{"/path\nInjected: evil", "/"},
		{"/path\x00null", "/"},
	}

	for _, tc := range testCases {
		got := sanitizeRedirectTarget(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizeRedirectTarget(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// TestMiddleware_NoStoreOnJSONErrors verifies writeJSONError sets Cache-Control: no-store
func TestMiddleware_NoStoreOnJSONErrors(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.Limits[og.ScopeFirstContact] = og.RateLimitRule{
		Rate:   1,
		Burst:  1,
		Cost:   1,
		Window: time.Minute,
	}

	engine, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	handler := Middleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust burst of 1
	r1 := httptest.NewRequest("GET", "/", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, r1)

	// Second request triggers 429 JSON error
	r2 := httptest.NewRequest("GET", "/", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, r2)

	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr2.Code)
	}
	cc := rr2.Header().Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("expected Cache-Control: no-store on JSON error, got %q", cc)
	}
	pragma := rr2.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("expected Pragma: no-cache on JSON error, got %q", pragma)
	}
}

// TestMiddleware_SyncsSessionCookie verifies that admitted sessions
// receive the session cookie with updated MaxAge matching session TTL.
func TestMiddleware_SyncsSessionCookie(t *testing.T) {
	clock := og.NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := og.DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false

	engine, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()

	ctx := context.Background()

	// Create admitted session
	sess, err := og.NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = og.StateAdmitted
	sess.ExpiresAt = clock.Now().Add(cfg.SessionTTL)
	if err := og.SaveSession(ctx, engine.Store(), sess, cfg.SessionTTL); err != nil {
		t.Fatal(err)
	}

	handler := Middleware(engine)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Session cookie should be emitted to synchronize browser MaxAge
	cookies := rr.Result().Cookies()
	var found *http.Cookie
	for _, c := range cookies {
		if c.Name == cfg.SessionCookieName {
			found = c
			break
		}
	}
	if found == nil {
		t.Fatalf("expected Set-Cookie header for admitted session")
	}
	if found.Value != sess.SessionID {
		t.Errorf("cookie value = %q, want %q", found.Value, sess.SessionID)
	}
	if found.MaxAge <= 0 {
		t.Errorf("cookie MaxAge = %d, want > 0", found.MaxAge)
	}
}
