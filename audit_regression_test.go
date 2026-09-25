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

func TestAudit_TokenValidatorPrincipalBound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPrincipalIDBytes = 4
	s, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := NewIdentityResolver(cfg, s, cfg.Clock, TokenValidatorFunc(func(context.Context, string) (string, bool, error) {
		return "oversized", true, nil
	}), nil)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("Authorization", "Bearer valid")
	if _, err := r.Resolve(req); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("got %v, want invalid token", err)
	}
}

func TestAudit_ConditionalLockRenewalOwnership(t *testing.T) {
	s, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Set(ctx, "lock", []byte("owner-a"), 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.CompareAndTouch(ctx, "lock", []byte("owner-b"), time.Second); err != nil || ok {
		t.Fatalf("wrong owner = %t, %v", ok, err)
	}
	if ok, err := s.CompareAndTouch(ctx, "lock", []byte("owner-a"), time.Second); err != nil || !ok {
		t.Fatalf("owner = %t, %v", ok, err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := s.Get(ctx, "lock"); err != nil {
		t.Fatalf("renewed lock expired: %v", err)
	}
}
