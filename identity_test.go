package onionguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

func TestIdentity_PrioritySequence(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()

	// Create a valid session in store
	validSess, err := NewSession(clock.Now(), 10)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	validSess.State = StateAdmitted
	validSess.ExpiresAt = clock.Now().Add(24 * time.Hour)
	if err := SaveSession(context.Background(), memStore, validSess, 24*time.Hour); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}

	tokenValidator := TokenValidatorFunc(func(ctx context.Context, rawToken string) (string, bool, error) {
		if rawToken == "valid-token-123" {
			return "service-worker", true, nil
		}
		if rawToken == "error-token" {
			return "", false, errors.New("validator database error")
		}
		return "", false, nil
	})

	principalExtractor := PrincipalExtractorFunc(func(r *http.Request) (string, bool) {
		if u := r.Header.Get("X-Authenticated-User"); u != "" {
			return u, true
		}
		return "", false
	})

	resolver := NewIdentityResolver(cfg, memStore, clock, tokenValidator, principalExtractor)

	tests := []struct {
		name          string
		authUser      string
		authHeader    string
		sessionCookie string
		wantKind      IdentityKind
		wantPrincipal string
		wantErr       bool
	}{
		{
			name:          "Priority 1: Authenticated Principal overrides all others",
			authUser:      "alice-admin",
			authHeader:    "Bearer valid-token-123",
			sessionCookie: validSess.SessionID,
			wantKind:      IdentityAuthenticated,
			wantPrincipal: "alice-admin",
			wantErr:       false,
		},
		{
			name:          "Priority 2: API Token overrides anonymous session",
			authUser:      "",
			authHeader:    "Bearer valid-token-123",
			sessionCookie: validSess.SessionID,
			wantKind:      IdentityAPIToken,
			wantPrincipal: "service-worker",
			wantErr:       false,
		},
		{
			name:          "Priority 2 Failure: Invalid API token rejects request (no fallback)",
			authUser:      "",
			authHeader:    "Bearer wrong-token",
			sessionCookie: validSess.SessionID,
			wantKind:      0,
			wantErr:       true,
		},
		{
			name:          "Priority 2 Error: Token validator error rejects request (no fallback)",
			authUser:      "",
			authHeader:    "Bearer error-token",
			sessionCookie: validSess.SessionID,
			wantKind:      0,
			wantErr:       true,
		},
		{
			name:          "Priority 3: Existing Admitted Anonymous Session",
			authUser:      "",
			authHeader:    "",
			sessionCookie: validSess.SessionID,
			wantKind:      IdentityAnonymous,
			wantPrincipal: validSess.SessionID,
			wantErr:       false,
		},
		{
			name:          "Priority 4: No credentials -> New Anonymous",
			authUser:      "",
			authHeader:    "",
			sessionCookie: "",
			wantKind:      IdentityAnonymousNew,
			wantPrincipal: "",
			wantErr:       false,
		},
		{
			name:          "Priority 4: Malformed session cookie -> New Anonymous",
			authUser:      "",
			authHeader:    "",
			sessionCookie: "too-short",
			wantKind:      IdentityAnonymousNew,
			wantPrincipal: "",
			wantErr:       false,
		},
		{
			name:          "Priority 4: Non-existent session cookie in store -> New Anonymous",
			authUser:      "",
			authHeader:    "",
			sessionCookie: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantKind:      IdentityAnonymousNew,
			wantPrincipal: "",
			wantErr:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/resource", nil)
			if tc.authUser != "" {
				req.Header.Set("X-Authenticated-User", tc.authUser)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.sessionCookie != "" {
				req.AddCookie(&http.Cookie{
					Name:  cfg.SessionCookieName,
					Value: tc.sessionCookie,
				})
			}

			id, err := resolver.Resolve(req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil, id: %+v", id)
				}
				if !errors.Is(err, ErrInvalidToken) {
					t.Errorf("expected ErrInvalidToken, got %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Kind != tc.wantKind {
				t.Errorf("expected Kind %v, got %v", tc.wantKind, id.Kind)
			}
			if tc.wantPrincipal != "" && id.PrincipalID != tc.wantPrincipal {
				t.Errorf("expected PrincipalID %q, got %q", tc.wantPrincipal, id.PrincipalID)
			}
		})
	}
}

func TestIdentity_API_URLToken_RejectionByDefault_Invariant22(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	tv := TokenValidatorFunc(func(ctx context.Context, rawToken string) (string, bool, error) {
		if rawToken == "secret-api-token" {
			return "api-client", true, nil
		}
		return "", false, nil
	})

	// Default config has AllowURLToken = false
	cfg := DefaultConfig()
	if cfg.AllowURLToken {
		t.Fatalf("DefaultConfig must have AllowURLToken == false")
	}

	resolverDefault := NewIdentityResolver(cfg, memStore, clock, tv, nil)

	// 1. Request with token in URL query parameter with default config
	req1 := httptest.NewRequest("GET", "/data?token=secret-api-token", nil)
	id1, err := resolverDefault.Resolve(req1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1.Kind != IdentityAnonymousNew {
		t.Errorf("expected URL token to be ignored by default (got %v)", id1.Kind)
	}

	// Also check ?api_key=...
	req1Key := httptest.NewRequest("GET", "/data?api_key=secret-api-token", nil)
	id1Key, err := resolverDefault.Resolve(req1Key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id1Key.Kind != IdentityAnonymousNew {
		t.Errorf("expected URL api_key to be ignored by default (got %v)", id1Key.Kind)
	}

	// 2. Explicitly allow URL tokens
	cfgAllowed := DefaultConfig()
	cfgAllowed.AllowURLToken = true
	resolverAllowed := NewIdentityResolver(cfgAllowed, memStore, clock, tv, nil)

	req2 := httptest.NewRequest("GET", "/data?token=secret-api-token", nil)
	id2, err := resolverAllowed.Resolve(req2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id2.Kind != IdentityAPIToken {
		t.Errorf("expected URL token to be accepted when AllowURLToken=true (got %v)", id2.Kind)
	}
	if id2.PrincipalID != "api-client" {
		t.Errorf("expected principal api-client, got %q", id2.PrincipalID)
	}
}

func TestIdentity_ZeroTrust_ClientIP_Invariants25_28(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	sess, err := NewSession(clock.Now(), 10)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	_ = SaveSession(context.Background(), memStore, sess, 1*time.Hour)

	resolver := NewIdentityResolver(DefaultConfig(), memStore, clock, nil, nil)

	// Two requests with identical session cookies but spoofed/different client IP headers
	reqA := httptest.NewRequest("GET", "/tor-resource", nil)
	reqA.RemoteAddr = "127.0.0.1:11111"
	reqA.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.195")
	reqA.Header.Set("X-Real-IP", "198.51.100.1")
	reqA.AddCookie(&http.Cookie{Name: "onionguard_session", Value: sess.SessionID})

	reqB := httptest.NewRequest("GET", "/tor-resource", nil)
	reqB.RemoteAddr = "10.0.0.99:54321"
	reqB.Header.Set("X-Forwarded-For", "192.0.2.1")
	reqB.Header.Set("X-Real-IP", "10.0.0.1")
	reqB.AddCookie(&http.Cookie{Name: "onionguard_session", Value: sess.SessionID})

	idA, errA := resolver.Resolve(reqA)
	if errA != nil {
		t.Fatalf("error resolving reqA: %v", errA)
	}

	idB, errB := resolver.Resolve(reqB)
	if errB != nil {
		t.Fatalf("error resolving reqB: %v", errB)
	}

	// 1. Both resolve to identical identity
	if idA.Kind != idB.Kind || idA.SessionID != idB.SessionID {
		t.Errorf("identities differ despite identical session cookies: %+v vs %+v", idA, idB)
	}

	// 2. RateLimitKey does not contain any IP address (Invariant 25)
	keyA := idA.RateLimitKey()
	keyB := idB.RateLimitKey()
	if keyA != keyB {
		t.Errorf("rate limit keys differ: %q vs %q", keyA, keyB)
	}
	if strings.Contains(keyA, "127.0.0.1") || strings.Contains(keyA, "198.51.100.1") || strings.Contains(keyA, "10.0.0.99") {
		t.Errorf("rate limit key leaked client IP: %q", keyA)
	}
}

func TestIdentity_String_Redaction_Invariant1_24(t *testing.T) {
	rawSessionID := "dGVzdC1zZXNzaW9uLWlkLWZvci1vbmlvbmd1YXJkMDEyMw"
	id := ClientIdentity{
		Kind:        IdentityAnonymous,
		PrincipalID: rawSessionID,
		TokenHash:   "a1b2c3d4e5f60718",
		SessionID:   rawSessionID,
	}

	str := id.String()
	goStr := id.GoString()

	// Ensure raw session ID never appears in String or GoString
	if strings.Contains(str, rawSessionID) {
		t.Errorf("raw session ID leaked in id.String(): %s", str)
	}
	if strings.Contains(goStr, rawSessionID) {
		t.Errorf("raw session ID leaked in id.GoString(): %s", goStr)
	}

	// Masked session ID must appear
	masked := MaskSessionID(rawSessionID)
	if !strings.Contains(str, masked) {
		t.Errorf("expected masked ID %q in id.String(): %s", masked, str)
	}
}

func TestIdentity_ContextPropagation(t *testing.T) {
	id := ClientIdentity{
		Kind:        IdentityAuthenticated,
		PrincipalID: "operator-1",
	}

	ctx := context.Background()
	_, found := ClientIdentityFromContext(ctx)
	if found {
		t.Fatalf("expected not found in empty context")
	}

	ctxWithID := WithClientIdentity(ctx, id)
	extracted, found := ClientIdentityFromContext(ctxWithID)
	if !found {
		t.Fatalf("expected to find ClientIdentity in context")
	}
	if extracted.Kind != id.Kind || extracted.PrincipalID != id.PrincipalID {
		t.Errorf("extracted identity does not match: %+v vs %+v", extracted, id)
	}
}

func TestIdentity_ResolveRaw_Equivalence(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	tv := TokenValidatorFunc(func(ctx context.Context, rawToken string) (string, bool, error) {
		if rawToken == "raw-token-abc" {
			return "raw-principal", true, nil
		}
		return "", false, nil
	})

	resolver := NewIdentityResolver(DefaultConfig(), memStore, clock, tv, nil)
	ctx := context.Background()

	// Principal
	id, err := resolver.ResolveRaw(ctx, "admin-user", "", "", "", "")
	if err != nil || id.Kind != IdentityAuthenticated || id.PrincipalID != "admin-user" {
		t.Errorf("unexpected resolve raw principal: %+v, %v", id, err)
	}

	// Bearer Token
	id, err = resolver.ResolveRaw(ctx, "", "Bearer raw-token-abc", "", "", "")
	if err != nil || id.Kind != IdentityAPIToken || id.PrincipalID != "raw-principal" {
		t.Errorf("unexpected resolve raw token: %+v, %v", id, err)
	}

	// X-API-Key
	id, err = resolver.ResolveRaw(ctx, "", "", "raw-token-abc", "", "")
	if err != nil || id.Kind != IdentityAPIToken || id.PrincipalID != "raw-principal" {
		t.Errorf("unexpected resolve raw api key: %+v, %v", id, err)
	}

	// Fallback AnonymousNew
	id, err = resolver.ResolveRaw(ctx, "", "", "", "", "")
	if err != nil || id.Kind != IdentityAnonymousNew {
		t.Errorf("unexpected resolve raw new anonymous: %+v, %v", id, err)
	}
}

func TestIdentity_Methods_Coverage(t *testing.T) {
	kinds := []IdentityKind{
		IdentityAuthenticated,
		IdentityAPIToken,
		IdentityAnonymous,
		IdentityAnonymousNew,
		IdentityKind(99),
	}

	for _, k := range kinds {
		s := k.String()
		if s == "" {
			t.Errorf("empty string representation for kind %d", k)
		}
	}

	authID := ClientIdentity{Kind: IdentityAuthenticated, PrincipalID: "p1"}
	if !authID.IsAdmitted() {
		t.Errorf("IdentityAuthenticated should be admitted")
	}
	if authID.RateLimitScope() != ScopeAuthenticated {
		t.Errorf("expected ScopeAuthenticated, got %v", authID.RateLimitScope())
	}
	if authID.RateLimitKey() != "auth:p1" {
		t.Errorf("expected auth:p1, got %s", authID.RateLimitKey())
	}

	tokenID := ClientIdentity{Kind: IdentityAPIToken, PrincipalID: "p2", TokenHash: "hash123"}
	if !tokenID.IsAdmitted() {
		t.Errorf("IdentityAPIToken should be admitted")
	}
	if tokenID.RateLimitScope() != ScopeAPIToken {
		t.Errorf("expected ScopeAPIToken, got %v", tokenID.RateLimitScope())
	}
	if tokenID.RateLimitKey() != "token:hash123" {
		t.Errorf("expected token:hash123, got %s", tokenID.RateLimitKey())
	}

	anonID := ClientIdentity{Kind: IdentityAnonymous, SessionID: "valid-session-id"}
	if !anonID.IsAdmitted() {
		t.Errorf("IdentityAnonymous should be admitted")
	}
	if anonID.RateLimitScope() != ScopeAnonymous {
		t.Errorf("expected ScopeAnonymous, got %v", anonID.RateLimitScope())
	}

	anonNewID := ClientIdentity{Kind: IdentityAnonymousNew}
	if anonNewID.IsAdmitted() {
		t.Errorf("IdentityAnonymousNew should NOT be admitted")
	}
	if anonNewID.RateLimitScope() != ScopeAnonymous {
		t.Errorf("expected ScopeAnonymous, got %v", anonNewID.RateLimitScope())
	}
	if anonNewID.RateLimitKey() != "anon_new:global" {
		t.Errorf("expected anon_new:global, got %s", anonNewID.RateLimitKey())
	}

	unknownID := ClientIdentity{Kind: IdentityKind(99)}
	if unknownID.RateLimitKey() != "unknown:global" {
		t.Errorf("expected unknown:global, got %s", unknownID.RateLimitKey())
	}
}
