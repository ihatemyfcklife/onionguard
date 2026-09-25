package onionguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"onionguard/store"
)

// =============================================================================
// CHALLENGER 2: ZERO-TRUST IP INVARIANT & STATIC ANALYSIS AUDIT SUITE
// =============================================================================

// TestChallenger_StaticAST_NoClientIPInProductionCode performs an AST-level and
// token-level static analysis across all production Go source files to prove that
// NO code path ever reads, parses, stores, logs, or hashes client IP addresses.
func TestChallenger_StaticAST_NoClientIPInProductionCode(t *testing.T) {
	prohibitedIdentifiers := map[string]bool{
		"RemoteAddr": true,
		"ClientIP":   true,
		"RemoteIP":   true,
	}

	prohibitedStrings := []string{
		"x-forwarded-for",
		"x-real-ip",
		"client-ip",
		"remoteip",
	}

	prohibitedSelectors := []struct {
		pkg string
		sel string
	}{
		{"net", "ParseIP"},
		{"net", "IP"},
		{"c", "IP"},
		{"c", "IPs"},
	}

	root := "."
	fset := token.NewFileSet()

	var checkedFiles int

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".agents" || d.Name() == ".git" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		// Only check production Go files (skip tests)
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		checkedFiles++
		node, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if parseErr != nil {
			t.Fatalf("failed to parse %s: %v", path, parseErr)
		}

		// Inspect AST nodes (excluding comments)
		ast.Inspect(node, func(n ast.Node) bool {
			if n == nil {
				return true
			}

			switch expr := n.(type) {
			case *ast.Ident:
				if prohibitedIdentifiers[expr.Name] {
					t.Errorf("VIOLATION in %s at line %d: prohibited identifier %q referenced in production code",
						path, fset.Position(expr.Pos()).Line, expr.Name)
				}
			case *ast.SelectorExpr:
				if ident, ok := expr.X.(*ast.Ident); ok {
					for _, ps := range prohibitedSelectors {
						if ident.Name == ps.pkg && expr.Sel.Name == ps.sel {
							t.Errorf("VIOLATION in %s at line %d: prohibited call/selector %s.%s in production code",
								path, fset.Position(expr.Pos()).Line, ps.pkg, ps.sel)
						}
					}
				}
			case *ast.BasicLit:
				if expr.Kind == token.STRING {
					cleanVal := strings.ToLower(strings.Trim(expr.Value, `"`))
					for _, ps := range prohibitedStrings {
						if cleanVal == ps {
							t.Errorf("VIOLATION in %s at line %d: prohibited IP header string literal %q in production code",
								path, fset.Position(expr.Pos()).Line, expr.Value)
						}
					}
				}
			}
			return true
		})

		return nil
	})

	if err != nil {
		t.Fatalf("WalkDir failed: %v", err)
	}

	if checkedFiles == 0 {
		t.Fatal("no production .go files were scanned")
	}
	t.Logf("Successfully scanned %d production .go files with zero client IP references", checkedFiles)
}

// TestChallenger_RateLimitKey_DecouplingAndScopeAudit verifies:
// 1. RateLimitKey across all scopes (auth, token, anon, anon_new, challenge)
// 2. Proof that keys depend strictly on cryptographic identifiers / masked hashes
// 3. RateLimiter.Allow behavior across all scopes.
func TestChallenger_RateLimitKey_DecouplingAndScopeAudit(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()
	limiter := NewRateLimiter(cfg, memStore, clock)
	ctx := context.Background()

	// 1. Authenticated
	authID := ClientIdentity{
		Kind:        IdentityAuthenticated,
		PrincipalID: "user-alpha-99",
	}
	authKey := authID.RateLimitKey()
	expectedAuthKey := "auth:user-alpha-99"
	if authKey != expectedAuthKey {
		t.Errorf("authenticated key mismatch: expected %q, got %q", expectedAuthKey, authKey)
	}

	// 2. APIToken (with token hash)
	rawAPIToken := "secret-api-bearer-token-1234567890"
	h := sha256.Sum256([]byte(rawAPIToken))
	tokHash := hex.EncodeToString(h[:8])
	tokenID := ClientIdentity{
		Kind:        IdentityAPIToken,
		PrincipalID: "service-bot",
		TokenHash:   tokHash,
	}
	tokenKey := tokenID.RateLimitKey()
	expectedTokenKey := "token:" + tokHash
	if tokenKey != expectedTokenKey {
		t.Errorf("api token key mismatch: expected %q, got %q", expectedTokenKey, tokenKey)
	}
	if strings.Contains(tokenKey, rawAPIToken) {
		t.Fatalf("api token key leaked raw token: %s", tokenKey)
	}

	// 3. APIToken (fallback when token hash empty)
	tokenIDNoHash := ClientIdentity{
		Kind:        IdentityAPIToken,
		PrincipalID: "service-bot",
	}
	if tokenIDNoHash.RateLimitKey() != "token:service-bot" {
		t.Errorf("api token fallback mismatch: expected token:service-bot, got %q", tokenIDNoHash.RateLimitKey())
	}

	// 4. Anonymous (admitted session)
	rawSession := "e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	anonID := ClientIdentity{
		Kind:        IdentityAnonymous,
		SessionID:   rawSession,
		PrincipalID: rawSession,
	}
	anonKey := anonID.RateLimitKey()
	expectedAnonKey := "anon:" + MaskSessionID(rawSession)
	if anonKey != expectedAnonKey {
		t.Errorf("anon key mismatch: expected %q, got %q", expectedAnonKey, anonKey)
	}
	if strings.Contains(anonKey, rawSession) {
		t.Fatalf("anon key leaked raw session ID: %s", anonKey)
	}

	// 5. AnonymousNew (unadmitted session with ID)
	anonNewID := ClientIdentity{
		Kind:        IdentityAnonymousNew,
		SessionID:   rawSession,
		PrincipalID: rawSession,
	}
	anonNewKey := anonNewID.RateLimitKey()
	expectedAnonNewKey := "anon_new:" + MaskSessionID(rawSession)
	if anonNewKey != expectedAnonNewKey {
		t.Errorf("anon_new key mismatch: expected %q, got %q", expectedAnonNewKey, anonNewKey)
	}
	if strings.Contains(anonNewKey, rawSession) {
		t.Fatalf("anon_new key leaked raw session ID: %s", anonNewKey)
	}

	// 6. AnonymousNew (first contact without session ID)
	anonNewGlobalID := ClientIdentity{
		Kind: IdentityAnonymousNew,
	}
	if anonNewGlobalID.RateLimitKey() != "anon_new:global" {
		t.Errorf("anon_new global mismatch: expected anon_new:global, got %q", anonNewGlobalID.RateLimitKey())
	}

	// 7. Unknown kind
	unknownID := ClientIdentity{
		Kind: IdentityKind(999),
	}
	if unknownID.RateLimitKey() != "unknown:global" {
		t.Errorf("unknown key mismatch: expected unknown:global, got %q", unknownID.RateLimitKey())
	}

	// Test Allow() across all identity tiers
	identities := []ClientIdentity{authID, tokenID, anonID, anonNewID, anonNewGlobalID}
	for _, id := range identities {
		res, err := limiter.Allow(ctx, id, "GET:/resource", 1)
		if err != nil {
			t.Errorf("unexpected error in Allow for %v: %v", id.Kind, err)
		}
		if !res.Allowed {
			t.Errorf("expected first request to be allowed for %v", id.Kind)
		}
	}

	// Rate limiting key decoupled from IP verification
	ipSpoofStrings := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "203.0.113.5",
	}
	for _, id := range identities {
		key := id.RateLimitKey()
		for _, ip := range ipSpoofStrings {
			if strings.Contains(key, ip) {
				t.Fatalf("rate limit key contains IP address: %s contains %s", key, ip)
			}
		}
	}
}

// TestChallenger_SecretRedaction_Config verifies Config.String() and GoString().
func TestChallenger_SecretRedaction_Config(t *testing.T) {
	secretPassword := "P@ssw0rd!SuperSecretRedis_987654321"
	cfg := DefaultConfig()
	cfg.StoreConfig.RedisPassword = secretPassword
	cfg.StoreConfig.Type = StoreTypeRedis

	str := cfg.String()
	goStr := cfg.GoString()

	if strings.Contains(str, secretPassword) {
		t.Fatalf("Config.String() leaked RedisPassword: %s", str)
	}
	if strings.Contains(goStr, secretPassword) {
		t.Fatalf("Config.GoString() leaked RedisPassword: %s", goStr)
	}
	if !strings.Contains(str, "[REDACTED]") {
		t.Errorf("Config.String() missing [REDACTED]: %s", str)
	}
}

// TestChallenger_SecretRedaction_StoreConfig verifies StoreConfig.String() and GoString().
func TestChallenger_SecretRedaction_StoreConfig(t *testing.T) {
	secretPassword := "m0r3_s3cr3ts_12345"
	sc := StoreConfig{
		Type:          StoreTypeRedis,
		RedisPassword: secretPassword,
		RedisAddr:     "redis.internal:6379",
	}

	str := sc.String()
	goStr := sc.GoString()

	if strings.Contains(str, secretPassword) {
		t.Fatalf("StoreConfig.String() leaked RedisPassword: %s", str)
	}
	if strings.Contains(goStr, secretPassword) {
		t.Fatalf("StoreConfig.GoString() leaked RedisPassword: %s", goStr)
	}
	if !strings.Contains(str, "[REDACTED]") {
		t.Errorf("StoreConfig.String() missing [REDACTED]: %s", str)
	}

	// Empty password should render [NONE]
	scEmpty := StoreConfig{Type: StoreTypeMemory}
	if !strings.Contains(scEmpty.String(), "[NONE]") {
		t.Errorf("StoreConfig.String() with empty password expected [NONE], got: %s", scEmpty.String())
	}
}

// TestChallenger_SecretRedaction_ClientIdentity verifies ClientIdentity.String() and GoString().
func TestChallenger_SecretRedaction_ClientIdentity(t *testing.T) {
	rawSessionID := "opaque-session-token-9876543210-abcdef"
	id := ClientIdentity{
		Kind:        IdentityAnonymous,
		PrincipalID: rawSessionID,
		TokenHash:   "a1b2c3d4e5f60718",
		SessionID:   rawSessionID,
	}

	str := id.String()
	goStr := id.GoString()

	if strings.Contains(str, rawSessionID) {
		t.Fatalf("ClientIdentity.String() leaked raw SessionID: %s", str)
	}
	if strings.Contains(goStr, rawSessionID) {
		t.Fatalf("ClientIdentity.GoString() leaked raw SessionID: %s", goStr)
	}
	masked := MaskSessionID(rawSessionID)
	if !strings.Contains(str, masked) {
		t.Errorf("ClientIdentity.String() missing masked session ID: %s", str)
	}
}

// TestChallenger_SecretRedaction_Session verifies Session.String() and GoString().
func TestChallenger_SecretRedaction_Session(t *testing.T) {
	rawSessionID := "secret-session-identity-token-11223344"
	sess := Session{
		SessionID:    rawSessionID,
		Kind:         IdentityAnonymous,
		State:        StateAdmitted,
		FirstSeen:    time.Now(),
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		RenewalCount: 2,
		MaxRenewals:  5,
	}

	str := sess.String()
	goStr := sess.GoString()

	if strings.Contains(str, rawSessionID) {
		t.Fatalf("Session.String() leaked raw SessionID: %s", str)
	}
	if strings.Contains(goStr, rawSessionID) {
		t.Fatalf("Session.GoString() leaked raw SessionID: %s", goStr)
	}
	masked := MaskSessionID(rawSessionID)
	if !strings.Contains(str, masked) {
		t.Errorf("Session.String() missing masked session ID: %s", str)
	}
}

// TestChallenger_SecretRedaction_ScrubSecrets tests regex-based sanitization in ScrubSecrets().
func TestChallenger_SecretRedaction_ScrubSecrets(t *testing.T) {
	cases := []struct {
		input    string
		leakWord string
		expected string
	}{
		{
			input:    "Authorization: Bearer secret_bearer_token_123456",
			leakWord: "secret_bearer_token_123456",
			expected: "Authorization: Bearer [REDACTED]",
		},
		{
			input:    "redis connection failed: password=super_secret_redis_pass; dial tcp 127.0.0.1",
			leakWord: "super_secret_redis_pass",
			expected: "redis connection failed: password=[REDACTED]; dial tcp 127.0.0.1",
		},
		{
			input:    "config error: password: secret_password_value",
			leakWord: "secret_password_value",
			expected: "config error: password: [REDACTED]",
		},
		{
			input:    "token=api_secret_token_abcdef12345",
			leakWord: "api_secret_token_abcdef12345",
			expected: "token=[REDACTED]",
		},
		{
			input:    "token: api_secret_token_abcdef12345",
			leakWord: "api_secret_token_abcdef12345",
			expected: "token: [REDACTED]",
		},
		{
			input:    "session=dGVzdC1zZXNzaW9uLWlkLWZvci1vbmlvbmd1YXJk",
			leakWord: "dGVzdC1zZXNzaW9uLWlkLWZvci1vbmlvbmd1YXJk",
			expected: "session=[REDACTED]",
		},
		{
			input:    "session: dGVzdC1zZXNzaW9uLWlkLWZvci1vbmlvbmd1YXJk",
			leakWord: "dGVzdC1zZXNzaW9uLWlkLWZvci1vbmlvbmd1YXJk",
			expected: "session: [REDACTED]",
		},
		{
			input:    "normal benign message without secrets",
			leakWord: "",
			expected: "normal benign message without secrets",
		},
		{
			input:    "",
			leakWord: "",
			expected: "",
		},
	}

	for i, tc := range cases {
		scrubbed := ScrubSecrets(tc.input)
		if tc.leakWord != "" && strings.Contains(scrubbed, tc.leakWord) {
			t.Errorf("case %d: ScrubSecrets leaked sensitive word %q in %q", i, tc.leakWord, scrubbed)
		}
		if scrubbed != tc.expected {
			t.Errorf("case %d: expected %q, got %q", i, tc.expected, scrubbed)
		}
	}
}

// TestChallenger_SecretRedaction_ClientSafeError verifies:
// 1. Error mapping to HTTP status code and standard sanitized messages
// 2. json.Marshal of AdmissionError NEVER serializes internal Err field
// 3. Error() method scrubs sensitive text from wrapped errors.
func TestChallenger_SecretRedaction_ClientSafeError(t *testing.T) {
	if ClientSafeError(nil) != nil {
		t.Error("expected nil for ClientSafeError(nil)")
	}

	sensitiveUnderlying := errors.New("dial tcp redis:6379 with password=super_secret_redis_pass: connection refused")
	wrappedErr := fmt.Errorf("%w: %v", ErrStoreUnavailable, sensitiveUnderlying)

	adm := ClientSafeError(wrappedErr)
	if adm == nil {
		t.Fatal("expected non-nil AdmissionError")
	}

	if adm.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", adm.StatusCode)
	}
	if adm.Code != "SERVICE_UNAVAILABLE" {
		t.Errorf("expected SERVICE_UNAVAILABLE, got %s", adm.Code)
	}
	if adm.Message != "Service temporarily unavailable. Please retry later." {
		t.Errorf("unexpected message: %s", adm.Message)
	}

	// 1. Verify JSON serialization does not leak underlying error or password
	jsonBytes, err := json.Marshal(adm)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, "super_secret_redis_pass") {
		t.Fatalf("JSON response leaked internal secret password: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "redis:6379") {
		t.Fatalf("JSON response leaked internal host details: %s", jsonStr)
	}

	// 2. Verify adm.Error() representation scrubs sensitive password
	errStr := adm.Error()
	if strings.Contains(errStr, "super_secret_redis_pass") {
		t.Fatalf("adm.Error() leaked internal secret password: %s", errStr)
	}
	if !strings.Contains(errStr, "[REDACTED]") {
		t.Errorf("adm.Error() expected to contain [REDACTED], got: %s", errStr)
	}

	// 3. Test other standard sentinel errors map safely
	testCases := []struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		{ErrRateLimited, 429, "RATE_LIMITED"},
		{ErrWaitTimeNotElapsed, 429, "WAIT_ROOM"},
		{ErrPayloadTooLarge, 413, "PAYLOAD_TOO_LARGE"},
		{ErrInvalidToken, 401, "UNAUTHORIZED"},
		{ErrSessionExpired, 403, "SESSION_INVALID"},
		{ErrSessionRevoked, 403, "SESSION_INVALID"},
		{ErrInvalidSession, 403, "SESSION_INVALID"},
		{ErrChallengeExpired, 403, "CHALLENGE_FAILED"},
		{ErrChallengeNotFound, 403, "CHALLENGE_FAILED"},
		{ErrChallengeFailed, 403, "CHALLENGE_FAILED"},
		{ErrMaxAttemptsExceeded, 403, "CHALLENGE_FAILED"},
		{ErrCapacityExceeded, 503, "SERVICE_UNAVAILABLE"},
		{ErrStoreUnavailable, 503, "SERVICE_UNAVAILABLE"},
		{ErrLockUnavailable, 503, "SERVICE_UNAVAILABLE"},
		{errors.New("unknown error with token=xyz"), 500, "INTERNAL_ERROR"},
	}

	for _, tc := range testCases {
		a := ClientSafeError(tc.err)
		if a.StatusCode != tc.wantStatus {
			t.Errorf("error %v: expected status %d, got %d", tc.err, tc.wantStatus, a.StatusCode)
		}
		if a.Code != tc.wantCode {
			t.Errorf("error %v: expected code %s, got %s", tc.err, tc.wantCode, a.Code)
		}
	}
}
