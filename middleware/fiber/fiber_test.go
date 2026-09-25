package fiber

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	og "onionguard"
)

func TestFiberMiddlewareDirectAdmission(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	app := fiber.New()
	app.Use(Middleware(eng))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	cookieHeader := resp.Header.Get("Set-Cookie")
	if cookieHeader == "" {
		t.Fatal("expected session cookie")
	}

	// Second request with the returned cookie
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Cookie", cookieHeader)
	resp2, err := app.Test(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 204 {
		t.Fatalf("expected 204, got %d", resp2.StatusCode)
	}
	cookieHeader2 := resp2.Header.Get("Set-Cookie")
	if cookieHeader2 == "" {
		t.Fatal("expected session cookie on second request")
	}
}

func TestFiberMiddlewareNilEngine(t *testing.T) {
	app := fiber.New()
	app.Use(Middleware(nil))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("expected 500 for nil engine, got %d", resp.StatusCode)
	}
}

func TestFiberMiddlewareWaitRoom(t *testing.T) {
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

	app := fiber.New()
	app.Use(Middleware(eng))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("expected 429 for wait room, got %d", resp.StatusCode)
	}
	cookie := resp.Header.Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("expected session cookie from wait room response")
	}

	clock.Advance(5 * time.Second)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Cookie", cookie)
	resp2, err := app.Test(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 204 {
		t.Fatalf("expected 204 after wait satisfied, got %d", resp2.StatusCode)
	}
}

func TestFiberMiddlewarePayloadLimit(t *testing.T) {
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

	app := fiber.New()
	app.Use(Middleware(eng))
	app.Post("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("12345"))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = 5
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}
}

func TestFiberMiddlewareSecurityHeaders(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.SecurityHeaders.Policy = og.HeaderOverride
	cfg.SecurityHeaders.XFrameOptions = "DENY"
	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	app := fiber.New()
	app.Use(Middleware(eng))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("expected X-Frame-Options DENY, got %q", resp.Header.Get("X-Frame-Options"))
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected X-Content-Type-Options nosniff, got %q", resp.Header.Get("X-Content-Type-Options"))
	}
}

func TestFiberMiddlewareChallengeFlow(t *testing.T) {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true
	cfg.RateLimit.Enabled = false
	eng, err := og.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	app := fiber.New()
	app.Use(Middleware(eng))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusNoContent) })

	// First request requires challenge
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403 challenge required, got %d", resp.StatusCode)
	}
	cookie := resp.Header.Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("expected session cookie")
	}

	// GET challenge page
	chReq := httptest.NewRequest(http.MethodGet, "/onionguard/challenge", nil)
	chReq.Header.Set("Cookie", cookie)
	chResp, err := app.Test(chReq)
	if err != nil {
		t.Fatal(err)
	}
	defer chResp.Body.Close()
	if chResp.StatusCode != 200 {
		t.Fatalf("expected 200 challenge page, got %d", chResp.StatusCode)
	}

	// Wrong answer POST
	postReq := httptest.NewRequest(http.MethodPost, "/onionguard/challenge", strings.NewReader("answer=WRONG"))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Cookie", cookie)
	postResp, err := app.Test(postReq)
	if err != nil {
		t.Fatal(err)
	}
	defer postResp.Body.Close()
	if postResp.StatusCode != 403 {
		t.Fatalf("expected 403 for wrong answer, got %d", postResp.StatusCode)
	}
}
