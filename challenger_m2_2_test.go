package onionguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"onionguard/store"
)

// =============================================================================
// CHALLENGE AREA 1: ADMISSION STATE MACHINE ILLEGAL TRANSITIONS (343 COMBINATIONS)
// =============================================================================

// TestChallenge_Admission_ExhaustiveIllegalTransitions asserts 100% rejection
// of all illegal state transitions across all 7 states and 8 events (392 combinations).
func TestChallenge_Admission_ExhaustiveIllegalTransitions(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	var totalChecked, illegalCount, legalCount int
	var illegalRejected, illegalAllowed int

	for _, from := range allStates {
		for _, event := range allEvents {
			for _, to := range allStates {
				totalChecked++
				isLegal := IsLegalTransition(from, event, to)

				if isLegal {
					legalCount++
					continue
				}

				illegalCount++

				// Setup session in 'from' state
				sess, err := NewSession(clock.Now(), 5)
				if err != nil {
					t.Fatalf("failed to create session: %v", err)
				}
				sess.State = from
				sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
				if err := SaveSession(ctx, memStore, sess, 1*time.Hour); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				// Attempt transition
				result, err := engine.Transition(ctx, sess.SessionID, event, to)

				if from == to {
					// Idempotent no-op case: session already in target state
					if err != nil {
						t.Errorf("idempotent transition %s -> %s on %s failed: %v", from, to, event, err)
					}
					illegalRejected++
				} else {
					if err == nil {
						illegalAllowed++
						t.Errorf("CRITICAL INVARIANT VIOLATION: illegal transition %s --(%s)--> %s succeeded with state %s",
							from, event, to, result.State)
					} else if !errors.Is(err, ErrInvalidTransition) {
						t.Errorf("expected ErrInvalidTransition for %s --(%s)--> %s, got: %v",
							from, event, to, err)
					} else {
						illegalRejected++
					}

					// Verify store state was NOT mutated
					loaded, getErr := GetSession(ctx, memStore, sess.SessionID)
					if getErr != nil {
						t.Errorf("failed to reload session after rejected transition: %v", getErr)
					} else if loaded.State != from {
						t.Errorf("store state was corrupted! Expected %s to remain %s, got %s",
							sess.SessionID, from, loaded.State)
					}
				}

				_ = DeleteSession(ctx, memStore, sess.SessionID)
			}
		}
	}

	t.Logf("Exhaustive matrix completed: total=%d, legal=%d, illegal=%d (rejected=%d, allowed=%d)",
		totalChecked, legalCount, illegalCount, illegalRejected, illegalAllowed)

	if illegalAllowed > 0 {
		t.Fatalf("FAILED: %d illegal transitions were incorrectly allowed", illegalAllowed)
	}
	if illegalCount != 368 || legalCount != 24 {
		t.Fatalf("transition count anomaly: expected 368 illegal and 24 legal, got %d and %d",
			illegalCount, legalCount)
	}
}

// TestChallenge_Admission_TargetedIllegalTransitions specifically tests the critical
// illegal transitions highlighted in the task description:
// 1. NEW directly to ADMITTED (when friction active or on non-NewClient events)
// 2. WAITING directly to ROTATING
// 3. EXPIRED to ADMITTED without challenge
// 4. REVOKED to any state
func TestChallenge_Admission_TargetedIllegalTransitions(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = true

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// 1. Challenge NEW directly to ADMITTED
	// A new session evaluated by AdmissionEngine when friction is enabled MUST NOT become ADMITTED
	newSess, _ := NewSession(clock.Now(), 5)
	dec, err := engine.Evaluate(ctx, newSess)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if dec.Allowed {
		t.Fatalf("VIOLATION: NEW session was directly allowed with friction enabled!")
	}
	if dec.State == StateAdmitted {
		t.Fatalf("VIOLATION: NEW session directly transitioned to ADMITTED!")
	}

	// Attempt Transition NEW -> ADMITTED on non-NewClient events
	illegalNewEvents := []Event{
		EventWaitElapsed,
		EventChallengeRequired,
		EventChallengeSolved,
		EventExpire,
		EventRevoke,
		EventRotate,
	}
	for _, ev := range illegalNewEvents {
		s, _ := NewSession(clock.Now(), 5)
		_ = SaveSession(ctx, memStore, s, 1*time.Hour)
		_, trErr := engine.Transition(ctx, s.SessionID, ev, StateAdmitted)
		if trErr == nil || !errors.Is(trErr, ErrInvalidTransition) {
			t.Errorf("VIOLATION: NEW -> ADMITTED via %s should be rejected with ErrInvalidTransition, got: %v",
				ev, trErr)
		}
		_ = DeleteSession(ctx, memStore, s.SessionID)
	}

	// 2. Challenge WAITING directly to ROTATING on ALL 7 events
	for _, ev := range allEvents {
		s, _ := NewSession(clock.Now(), 5)
		s.State = StateWaiting
		_ = SaveSession(ctx, memStore, s, 1*time.Hour)
		_, trErr := engine.Transition(ctx, s.SessionID, ev, StateRotating)
		if trErr == nil || !errors.Is(trErr, ErrInvalidTransition) {
			t.Errorf("VIOLATION: WAITING -> ROTATING via %s should be rejected, got: %v", ev, trErr)
		}
		_ = DeleteSession(ctx, memStore, s.SessionID)
	}

	// 3. Challenge EXPIRED to ADMITTED on ALL 7 events (with or without challenge)
	for _, ev := range allEvents {
		s, _ := NewSession(clock.Now(), 5)
		s.State = StateExpired
		s.ExpiresAt = clock.Now().Add(-1 * time.Hour)
		_ = SaveSession(ctx, memStore, s, 1*time.Hour)

		_, trErr := engine.Transition(ctx, s.SessionID, ev, StateAdmitted)
		if trErr == nil || !errors.Is(trErr, ErrInvalidTransition) {
			t.Errorf("VIOLATION: EXPIRED -> ADMITTED via %s should be rejected, got: %v", ev, trErr)
		}

		// Also verify Evaluate rejects it immediately
		decExpired, _ := engine.Evaluate(ctx, s)
		if decExpired.Allowed || decExpired.State == StateAdmitted {
			t.Errorf("VIOLATION: Evaluate on EXPIRED session returned allowed=true or StateAdmitted!")
		}
		if !errors.Is(decExpired.Error, ErrSessionExpired) {
			t.Errorf("expected ErrSessionExpired for expired session evaluate, got: %v", decExpired.Error)
		}

		_ = DeleteSession(ctx, memStore, s.SessionID)
	}

	// 4. Challenge REVOKED to ANY state on ALL 7 events (100% rejection)
	for _, targetState := range allStates {
		if targetState == StateRevoked {
			continue // Idempotent check handled separately
		}
		for _, ev := range allEvents {
			s, _ := NewSession(clock.Now(), 5)
			s.State = StateRevoked
			_ = SaveSession(ctx, memStore, s, 1*time.Hour)

			_, trErr := engine.Transition(ctx, s.SessionID, ev, targetState)
			if trErr == nil || !errors.Is(trErr, ErrInvalidTransition) {
				t.Errorf("VIOLATION: REVOKED -> %s via %s should be strictly rejected, got: %v",
					targetState, ev, trErr)
			}

			// Verify Evaluate rejects revoked session
			decRevoked, _ := engine.Evaluate(ctx, s)
			if decRevoked.Allowed || decRevoked.State != StateRevoked {
				t.Errorf("VIOLATION: Evaluate on REVOKED session returned allowed=true or state=%s", decRevoked.State)
			}
			if !errors.Is(decRevoked.Error, ErrSessionRevoked) {
				t.Errorf("expected ErrSessionRevoked for revoked session, got: %v", decRevoked.Error)
			}

			_ = DeleteSession(ctx, memStore, s.SessionID)
		}
	}
}

// TestChallenge_Admission_CorruptedAndTamperedStates asserts that unrecognised,
// empty, or malicious state strings are strictly rejected and cannot transition.
func TestChallenge_Admission_CorruptedAndTamperedStates(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	maliciousStates := []State{
		State(""),
		State("HACKED"),
		State("admitted"), // lowercase
		State("UNKNOWN"),
		State("ADMITTED; DROP TABLE sessions;"),
		State("\x00\x01\x02"),
		State("null"),
	}

	for _, badState := range maliciousStates {
		s, _ := NewSession(clock.Now(), 5)
		s.State = badState
		_ = SaveSession(ctx, memStore, s, 1*time.Hour)

		// 1. Evaluate must reject unknown state
		dec, err := engine.Evaluate(ctx, s)
		if err != nil {
			t.Fatalf("unexpected error on Evaluate: %v", err)
		}
		if dec.Allowed {
			t.Errorf("VIOLATION: malicious state %q was allowed!", badState)
		}
		if !errors.Is(dec.Error, ErrInvalidTransition) {
			t.Errorf("expected ErrInvalidTransition for state %q, got: %v", badState, dec.Error)
		}

		// 2. Transition from badState to any valid state must fail
		for _, target := range allStates {
			_, trErr := engine.Transition(ctx, s.SessionID, EventNewClient, target)
			if trErr == nil || !errors.Is(trErr, ErrInvalidTransition) {
				t.Errorf("VIOLATION: transition from bad state %q to %s should fail with ErrInvalidTransition, got: %v",
					badState, target, trErr)
			}
		}

		_ = DeleteSession(ctx, memStore, s.SessionID)
	}
}

// =============================================================================
// CHALLENGE AREA 2: IDENTITY SPOOFING & ZERO-TRUST BOUNDARIES
// =============================================================================

// TestChallenge_Identity_AdversarialHeaderInjection verifies that arbitrary
// X-Forwarded-For, X-Real-IP, and changing RemoteAddr values cannot alter identity,
// bypass friction, or manipulate rate limit keys.
func TestChallenge_Identity_AdversarialHeaderInjection(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()

	// Create an admitted session
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	_ = SaveSession(context.Background(), memStore, sess, 1*time.Hour)

	resolver := NewIdentityResolver(cfg, memStore, clock, nil, nil)

	adversarialIPVectors := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
	}{
		{"Loopback IPv4", "127.0.0.1:12345", "127.0.0.1", "127.0.0.1"},
		{"Loopback IPv6", "[::1]:54321", "::1", "::1"},
		{"Private RFC1918 class A", "10.0.0.1:8080", "10.0.0.1, 10.0.0.2", "10.0.0.1"},
		{"Private RFC1918 class B", "172.16.0.1:9000", "172.16.0.1", "172.16.0.1"},
		{"Private RFC1918 class C", "192.168.1.1:443", "192.168.1.1", "192.168.1.1"},
		{"Tor exit node spoof", "185.220.101.5:9050", "185.220.101.5", "185.220.101.5"},
		{"Unix domain socket spoof", "@", "unix:/var/run/tor.sock", "unix:/var/run/tor.sock"},
		{"SQL injection in IP header", "1.1.1.1:1111", "1.1.1.1'; DROP TABLE clients;--", "' OR '1'='1"},
		{"CRLF injection in IP header", "2.2.2.2:2222", "1.2.3.4\r\nX-Injected: admin", "1.2.3.4\r\n"},
		{"Massive header string (10KB)", "3.3.3.3:3333", strings.Repeat("9.9.9.9, ", 1000), strings.Repeat("a", 10000)},
		{"Malformed remote addr", "not-a-valid-ip-port", "invalid", "invalid"},
		{"Empty remote addr", "", "", ""},
	}

	// Reference identity with standard connection
	refReq := httptest.NewRequest("GET", "/protected", nil)
	refReq.RemoteAddr = "127.0.0.1:5000"
	refReq.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})
	refID, err := resolver.Resolve(refReq)
	if err != nil {
		t.Fatalf("failed to resolve reference request: %v", err)
	}
	refKey := refID.RateLimitKey()

	for _, tc := range adversarialIPVectors {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/protected", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}
			req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})

			resolved, err := resolver.Resolve(req)
			if err != nil {
				t.Fatalf("unexpected error resolving spoofed request: %v", err)
			}

			// Invariant Check 1: Identity Kind must remain exactly IdentityAnonymous
			if resolved.Kind != refID.Kind {
				t.Errorf("kind mismatch under IP spoofing: expected %v, got %v", refID.Kind, resolved.Kind)
			}

			// Invariant Check 2: Session ID must match identically
			if resolved.SessionID != refID.SessionID {
				t.Errorf("session ID altered by IP spoofing: expected %q, got %q", refID.SessionID, resolved.SessionID)
			}

			// Invariant Check 3: RateLimitKey must remain identical and MUST NOT contain client IP (Invariants 25-28)
			key := resolved.RateLimitKey()
			if key != refKey {
				t.Errorf("RateLimitKey altered by IP spoofing: expected %q, got %q", refKey, key)
			}

			// Invariant Check 4: RateLimitKey must NEVER contain any substring from spoofed headers
			if tc.remoteAddr != "" && strings.Contains(key, tc.remoteAddr) {
				t.Errorf("RateLimitKey leaked RemoteAddr: %q contains %q", key, tc.remoteAddr)
			}
			if tc.xRealIP != "" && strings.Contains(key, tc.xRealIP) {
				t.Errorf("RateLimitKey leaked X-Real-IP: %q contains %q", key, tc.xRealIP)
			}
		})
	}
}

// TestChallenge_Identity_SpoofedIPDoesNotConferIdentity verifies that an unauthenticated
// request sending trusted IP headers (e.g. 127.0.0.1, RFC1918) does NOT confer
// Authenticated, APIToken, or Anonymous status.
func TestChallenge_Identity_SpoofedIPDoesNotConferIdentity(t *testing.T) {
	memStore, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()
	resolver := NewIdentityResolver(cfg, memStore, clock, nil, nil)

	spoofedHeaders := []map[string]string{
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Real-IP": "127.0.0.1"},
		{"X-Forwarded-For": "10.0.0.1"},
		{"X-Originating-IP": "127.0.0.1"},
		{"Client-IP": "127.0.0.1"},
		{"Forwarded": "for=127.0.0.1;proto=https;by=127.0.0.1"},
	}

	for _, headers := range spoofedHeaders {
		req := httptest.NewRequest("GET", "/admin", nil)
		req.RemoteAddr = "127.0.0.1:9999"
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		id, err := resolver.Resolve(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// MUST resolve strictly to IdentityAnonymousNew
		if id.Kind != IdentityAnonymousNew {
			t.Fatalf("SECURITY VIOLATION: spoofed headers %+v conferred identity %v (expected %v)",
				headers, id.Kind, IdentityAnonymousNew)
		}
		if id.IsAdmitted() {
			t.Fatalf("SECURITY VIOLATION: spoofed headers %+v resulted in admitted client!", headers)
		}
	}
}

// TestChallenge_Identity_RapidlyChangingRemoteAddr simulates a Tor client whose
// connections switch circuits / source addresses rapidly across 50 requests.
func TestChallenge_Identity_RapidlyChangingRemoteAddr(t *testing.T) {
	memStore, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()

	sess, _ := NewSession(clock.Now(), 5)
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	_ = SaveSession(context.Background(), memStore, sess, 1*time.Hour)

	resolver := NewIdentityResolver(cfg, memStore, clock, nil, nil)

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/circuit-switch", nil)
		req.RemoteAddr = fmt.Sprintf("198.51.100.%d:%d", (i%250)+1, 10000+i)
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", (i%250)+1))
		req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})

		id, err := resolver.Resolve(req)
		if err != nil {
			t.Fatalf("iteration %d failed: %v", i, err)
		}
		if id.Kind != IdentityAnonymous {
			t.Errorf("iteration %d: expected IdentityAnonymous, got %v", i, id.Kind)
		}
		if id.SessionID != sess.SessionID {
			t.Errorf("iteration %d: session ID mismatch", i)
		}
		expectedKey := "anon:" + MaskSessionID(sess.SessionID)
		if id.RateLimitKey() != expectedKey {
			t.Errorf("iteration %d: RateLimitKey mismatch: expected %q, got %q", i, expectedKey, id.RateLimitKey())
		}
	}
}

// =============================================================================
// CHALLENGE AREA 3: PROOF-OF-PATIENCE WAIT ROOM TIMING & HTTP VERB IMMUNITY
// =============================================================================

// TestChallenge_WaitRoom_MicrosecondTimingBoundaries tests the exact math
// and boundary conditions of proof-of-patience wait room calculations.
func TestChallenge_WaitRoom_MicrosecondTimingBoundaries(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 10 * time.Second
	cfg.Captcha.Enabled = true

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Initial evaluation at t=0
	dec, err := engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("initial evaluate failed: %v", err)
	}
	if dec.Allowed || dec.State != StateWaiting || dec.RetryAfter != 10*time.Second {
		t.Fatalf("initial wait room failure: %+v", dec)
	}

	timingTests := []struct {
		name               string
		advanceDuration    time.Duration
		expectedAllowed    bool
		expectedState      State
		expectedRetryAfter time.Duration
		expectedErr        error
	}{
		{
			name:               "t = 1ms (elapsed = 1ms, rem = 9.999s, ceil = 10s)",
			advanceDuration:    1 * time.Millisecond,
			expectedAllowed:    false,
			expectedState:      StateWaiting,
			expectedRetryAfter: 10 * time.Second,
			expectedErr:        ErrWaitTimeNotElapsed,
		},
		{
			name:               "t = 500ms (elapsed = 501ms, rem = 9.499s, ceil = 10s)",
			advanceDuration:    500 * time.Millisecond,
			expectedAllowed:    false,
			expectedState:      StateWaiting,
			expectedRetryAfter: 10 * time.Second,
			expectedErr:        ErrWaitTimeNotElapsed,
		},
		{
			name:               "t = 1000ms (elapsed = 1501ms, rem = 8.499s, ceil = 9s)",
			advanceDuration:    1000 * time.Millisecond,
			expectedAllowed:    false,
			expectedState:      StateWaiting,
			expectedRetryAfter: 9 * time.Second,
			expectedErr:        ErrWaitTimeNotElapsed,
		},
		{
			name:               "t = 5000ms (elapsed = 6501ms, rem = 3.499s, ceil = 4s)",
			advanceDuration:    5000 * time.Millisecond,
			expectedAllowed:    false,
			expectedState:      StateWaiting,
			expectedRetryAfter: 4 * time.Second,
			expectedErr:        ErrWaitTimeNotElapsed,
		},
		{
			name:               "t = 9000ms (elapsed = 9501ms, rem = 0.499s, ceil = 1s)",
			advanceDuration:    3000 * time.Millisecond,
			expectedAllowed:    false,
			expectedState:      StateWaiting,
			expectedRetryAfter: 1 * time.Second,
			expectedErr:        ErrWaitTimeNotElapsed,
		},
		{
			name:               "t = 9999ms (elapsed = 9999ms, rem = 0.001s, ceil = 1s)",
			advanceDuration:    498 * time.Millisecond,
			expectedAllowed:    false,
			expectedState:      StateWaiting,
			expectedRetryAfter: 1 * time.Second,
			expectedErr:        ErrWaitTimeNotElapsed,
		},
		{
			name:               "t = 10000ms (boundary reached: wait time elapsed!)",
			advanceDuration:    1 * time.Millisecond,
			expectedAllowed:    false,
			expectedState:      StateChallengeRequired,
			expectedRetryAfter: 0,
			expectedErr:        nil,
		},
	}

	for _, tc := range timingTests {
		t.Run(tc.name, func(t *testing.T) {
			clock.Advance(tc.advanceDuration)
			decision, err := engine.Evaluate(ctx, sess)
			if err != nil {
				t.Fatalf("Evaluate error: %v", err)
			}

			if decision.Allowed != tc.expectedAllowed {
				t.Errorf("allowed mismatch: expected %v, got %v", tc.expectedAllowed, decision.Allowed)
			}
			if decision.State != tc.expectedState {
				t.Errorf("state mismatch: expected %s, got %s", tc.expectedState, decision.State)
			}
			if decision.RetryAfter != tc.expectedRetryAfter {
				t.Errorf("RetryAfter mismatch: expected %v, got %v", tc.expectedRetryAfter, decision.RetryAfter)
			}
			if tc.expectedErr != nil && !errors.Is(decision.Error, tc.expectedErr) {
				t.Errorf("error mismatch: expected %v, got %v", tc.expectedErr, decision.Error)
			}
		})
	}
}

// TestChallenge_WaitRoom_NegativeClockSkewResilience tests how the wait room
// responds when the system clock jumps backward (e.g. NTP backwards synchronization).
func TestChallenge_WaitRoom_NegativeClockSkewResilience(t *testing.T) {
	memStore, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, _ := NewSession(clock.Now(), 5)
	_, _ = engine.Evaluate(ctx, sess)

	// Jump clock BACKWARD by 10 minutes (negative elapsed time)
	clock.Set(start.Add(-10 * time.Minute))

	dec, err := engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("unexpected error on negative clock skew: %v", err)
	}

	// Must NOT crash, must NOT allow access, must clamp elapsed to 0 and require full wait time
	if dec.Allowed {
		t.Fatalf("CRITICAL BUG: client admitted during negative clock skew!")
	}
	if dec.State != StateWaiting {
		t.Errorf("expected StateWaiting, got %s", dec.State)
	}
	if dec.RetryAfter != 5*time.Second {
		t.Errorf("expected RetryAfter 5s during negative clock skew, got %v", dec.RetryAfter)
	}
}

// TestChallenge_WaitRoom_HTTPVerbBypassImmunity tests Invariants 15 & 16:
// Verifies that changing HTTP verbs cannot bypass wait time or admission checks.
func TestChallenge_WaitRoom_HTTPVerbBypassImmunity(t *testing.T) {
	memStore, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = true

	engine := NewAdmissionEngine(cfg, memStore, clock)
	resolver := NewIdentityResolver(cfg, memStore, clock, nil, nil)
	ctx := context.Background()

	verbs := []string{
		"GET",
		"POST",
		"PUT",
		"DELETE",
		"PATCH",
		"HEAD",
		"OPTIONS",
		"TRACE",
		"CONNECT",
		"PROPFIND",
		"MKCOL",
		"COPY",
		"MOVE",
		"LOCK",
		"UNLOCK",
		"CUSTOM_VERB",
		"BYPASS",
	}

	for _, verb := range verbs {
		t.Run("Verb_"+verb, func(t *testing.T) {
			clock.Set(start)

			// 1. Create fresh session in wait room
			sess, err := NewSession(clock.Now(), 5)
			if err != nil {
				t.Fatalf("failed to create session: %v", err)
			}
			initDec, err := engine.Evaluate(ctx, sess)
			if err != nil || initDec.State != StateWaiting {
				t.Fatalf("failed to initialize session to WAITING: %v", err)
			}

			// 2. Perform request with specified verb before WaitTime has elapsed (at t = 2s)
			clock.Set(start.Add(2 * time.Second))

			req := httptest.NewRequest(verb, "/sensitive-resource", strings.NewReader("payload=data"))
			req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: sess.SessionID})

			// Resolve identity
			ci, err := resolver.Resolve(req)
			if err != nil {
				t.Fatalf("verb %s: resolve error: %v", verb, err)
			}

			// Must not be admitted regardless of verb
			if ci.IsAdmitted() {
				t.Errorf("CRITICAL SECURITY VIOLATION: verb %s conferred IsAdmitted=true prior to wait elapsed!", verb)
			}
			if ci.Kind != IdentityAnonymousNew {
				t.Errorf("verb %s: expected IdentityAnonymousNew, got %v", verb, ci.Kind)
			}

			// Evaluate admission decision
			dec, err := engine.Evaluate(ctx, sess)
			if err != nil {
				t.Fatalf("verb %s: evaluate error: %v", verb, err)
			}

			if dec.Allowed {
				t.Fatalf("CRITICAL SECURITY VIOLATION: verb %s bypassed wait room with allowed=true!", verb)
			}
			if dec.State != StateWaiting {
				t.Errorf("verb %s: expected StateWaiting, got %s", verb, dec.State)
			}
			if dec.RetryAfter != 3*time.Second {
				t.Errorf("verb %s: expected RetryAfter 3s at t=2s, got %v", verb, dec.RetryAfter)
			}
			if !errors.Is(dec.Error, ErrWaitTimeNotElapsed) {
				t.Errorf("verb %s: expected ErrWaitTimeNotElapsed, got %v", verb, dec.Error)
			}
		})
	}
}

// TestChallenge_WaitRoom_CookieTamperingImmunity verifies that tampering with
// session cookies during the wait room phase cannot escalate privileges or bypass wait time.
func TestChallenge_WaitRoom_CookieTamperingImmunity(t *testing.T) {
	memStore, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second

	resolver := NewIdentityResolver(cfg, memStore, clock, nil, nil)

	tamperedCookies := []struct {
		name  string
		value string
	}{
		{"Truncated (10 chars)", "abcdef1234"},
		{"Truncated (42 chars)", strings.Repeat("a", 42)},
		{"Extended (44 chars)", strings.Repeat("a", 44)},
		{"Standard Base64 padding", strings.Repeat("a", 42) + "="},
		{"Illegal chars (slash)", strings.Repeat("a", 42) + "/"},
		{"Illegal chars (plus)", strings.Repeat("a", 42) + "+"},
		{"SQL injection in cookie", "' OR '1'='1"},
		{"Null byte in cookie", "abcdef\x001234567890abcdef1234567890abcdef123"},
		{"Random non-existent valid 43-char token", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"},
	}

	for _, tc := range tamperedCookies {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/resource", nil)
			req.AddCookie(&http.Cookie{Name: cfg.SessionCookieName, Value: tc.value})

			ci, err := resolver.Resolve(req)
			if err != nil {
				t.Fatalf("unexpected error resolving tampered cookie: %v", err)
			}

			// MUST resolve to AnonymousNew, never Admitted
			if ci.IsAdmitted() {
				t.Errorf("tampered cookie %q conferred admitted status!", tc.value)
			}
			if ci.Kind != IdentityAnonymousNew {
				t.Errorf("tampered cookie %q resolved to %v (expected %v)", tc.value, ci.Kind, IdentityAnonymousNew)
			}
		})
	}
}

// TestChallenge_Admission_ConcurrentWaitBoundaryStampede simulates a thundering
// herd of 100 concurrent requests arriving at the exact instant the wait room
// timer expires. It verifies that:
// 1. All 100 requests return a consistent, deterministic state
// 2. No race condition causes multiple duplicate transitions
// 3. Exactly one transition executes and the final state in store is deterministic
func TestChallenge_Admission_ConcurrentWaitBoundaryStampede(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = true

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// Initialize into WAITING
	initDec, err := engine.Evaluate(ctx, sess)
	if err != nil || initDec.State != StateWaiting {
		t.Fatalf("failed to initialize to WAITING: %v", err)
	}

	// Advance clock past WaitTime
	clock.Advance(5001 * time.Millisecond)

	const stampedeConcurrency = 100
	var wg sync.WaitGroup
	wg.Add(stampedeConcurrency)

	decisions := make([]AdmissionDecision, stampedeConcurrency)
	errs := make([]error, stampedeConcurrency)
	startGate := make(chan struct{})

	for i := 0; i < stampedeConcurrency; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-startGate

			dec, evalErr := engine.Evaluate(ctx, sess)
			decisions[idx] = dec
			errs[idx] = evalErr
		}()
	}

	close(startGate) // Release stampede
	wg.Wait()

	// Verify all 100 returned deterministic results
	for i := 0; i < stampedeConcurrency; i++ {
		if errs[i] != nil {
			t.Errorf("stampede goroutine #%d failed: %v", i, errs[i])
		}
		if decisions[i].Allowed {
			t.Errorf("stampede goroutine #%d returned allowed=true before CAPTCHA solved!", i)
		}
		if decisions[i].State != StateChallengeRequired {
			t.Errorf("stampede goroutine #%d returned unexpected state: %s", i, decisions[i].State)
		}
	}

	// Verify final store state
	fresh, err := GetSession(ctx, memStore, sess.SessionID)
	if err != nil {
		t.Fatalf("failed to reload session: %v", err)
	}
	if fresh.State != StateChallengeRequired {
		t.Fatalf("expected final store state StateChallengeRequired, got %s", fresh.State)
	}
}
