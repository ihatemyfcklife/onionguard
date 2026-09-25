package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	og "onionguard"
)

func newTestEngine(t *testing.T) (*og.Engine, og.Config) {
	t.Helper()
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	return eng, cfg
}

func TestHTTPMiddlewareAdmissionAndCookie(t *testing.T) {
	eng, _ := newTestEngine(t)
	h := Middleware(eng)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := og.ClientIdentityFromContext(r.Context()); !ok {
			t.Error("missing identity in context")
		}
		w.WriteHeader(204)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if len(w.Result().Cookies()) != 1 {
		t.Fatalf("expected session cookie, got %#v", w.Result().Cookies())
	}
}

func TestHTTPMiddlewareWaitRoomAndRetryAfter(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.RateLimit.Enabled = false
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = false
	clock := og.NewTestClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cfg.Clock = clock
	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	h := Middleware(eng)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 429 {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") != "5" {
		t.Fatalf("expected Retry-After 5, got %q", w.Header().Get("Retry-After"))
	}
	cookie := w.Result().Cookies()[0]
	clock.Advance(5 * time.Second)
	r = httptest.NewRequest(http.MethodPost, "/action", strings.NewReader("x"))
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("expected admission after wait, got %d %s", w.Code, w.Body.String())
	}
}

func TestHTTPMiddlewarePayloadLimit(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.MaxBodyBytes = 4
	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	h := Middleware(eng)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
	r.ContentLength = 5
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestHTTPMiddlewareChallengeNoJS(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true
	cfg.RateLimit.Enabled = false
	clock := og.NewTestClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cfg.Clock = clock
	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	h := Middleware(eng)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("expected 403 challenge, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "<script") || !strings.Contains(body, "data:image/png;base64,") {
		t.Fatal("challenge page is not zero-JS/data-URI")
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP")
	}
	cookie := w.Result().Cookies()[0]
	chReq := httptest.NewRequest(http.MethodGet, cfg.Captcha.EndpointPath, nil)
	chReq.AddCookie(cookie)
	chW := httptest.NewRecorder()
	h.ServeHTTP(chW, chReq)
	if chW.Code != 200 {
		t.Fatalf("challenge GET expected 200, got %d", chW.Code)
	}
}

func TestHTTPMiddlewareInvalidToken(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	eng, err := og.New(cfg, og.WithTokenValidator(og.TokenValidatorFunc(func(ctx context.Context, raw string) (string, bool, error) { return "", false, errors.New("db secret") })))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	h := Middleware(eng)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer abc")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "db secret") {
		t.Fatal("internal error leaked")
	}
}
