package onionguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEngineEndToEndWaitAndAdmission(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.Clock = clock
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 3 * time.Second
	cfg.Captcha.Enabled = false
	cfg.RateLimit.Enabled = false
	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	dec, err := eng.AuthorizeRequest(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Admission.State != StateWaiting {
		t.Fatalf("expected waiting, got %s", dec.Admission.State)
	}
	if dec.Session == nil {
		t.Fatal("missing session")
	}
	r.AddCookie(eng.SessionCookie(dec.Session))
	clock.Advance(3 * time.Second)
	dec, err = eng.AuthorizeRequest(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.Admission.Allowed || dec.Admission.State != StateAdmitted {
		t.Fatalf("expected admitted, got %+v", dec.Admission)
	}
}
