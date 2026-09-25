package onionguard

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"onionguard/store"
)

var allStates = []State{
	StateNew,
	StateWaiting,
	StateChallengeRequired,
	StateAdmitted,
	StateExpired,
	StateRevoked,
	StateRotating,
}

var allEvents = []Event{
	EventNewClient,
	EventWaitElapsed,
	EventChallengeRequired,
	EventChallengeSolved,
	EventChallengeFailed,
	EventExpire,
	EventRevoke,
	EventRotate,
}

func TestAdmission_TransitionMatrix_LegalAndIllegal(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// Test all 7 x 7 x 7 = 343 combinations
	for _, from := range allStates {
		for _, event := range allEvents {
			for _, to := range allStates {
				isLegal := IsLegalTransition(from, event, to)

				// Create session in 'from' state
				sess, err := NewSession(clock.Now(), 5)
				if err != nil {
					t.Fatalf("failed to create session: %v", err)
				}
				sess.State = from
				sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
				if err := SaveSession(ctx, memStore, sess, 1*time.Hour); err != nil {
					t.Fatalf("failed to save session: %v", err)
				}

				result, err := engine.Transition(ctx, sess.SessionID, event, to)

				if isLegal {
					if err != nil {
						t.Errorf("expected legal transition %s --(%s)--> %s to succeed, got error: %v",
							from, event, to, err)
					} else {
						if result.State != to {
							t.Errorf("transition %s --(%s)--> %s: expected state %s, got %s",
								from, event, to, to, result.State)
						}
						// Verify state persisted in store
						loaded, getErr := GetSession(ctx, memStore, sess.SessionID)
						if getErr != nil {
							t.Errorf("failed to reload session: %v", getErr)
						} else if loaded.State != to {
							t.Errorf("store state mismatch: expected %s, got %s", to, loaded.State)
						}
					}
				} else {
					if from == to {
						// Idempotent no-op check: Transition returns sess if already in target state
						if err != nil {
							t.Errorf("idempotent transition to same state failed: %v", err)
						}
					} else {
						if err == nil {
							t.Errorf("expected illegal transition %s --(%s)--> %s to fail, but succeeded with state %s",
								from, event, to, result.State)
						} else if !errors.Is(err, ErrInvalidTransition) {
							t.Errorf("expected ErrInvalidTransition for %s --(%s)--> %s, got: %v",
								from, event, to, err)
						}
					}
				}

				// Clean up store entry for next iteration
				_ = DeleteSession(ctx, memStore, sess.SessionID)
			}
		}
	}
}

func TestAdmission_TerminalState_Revoked(t *testing.T) {
	// Revoked is a strict terminal state: no outbound transitions are legal under any event
	for _, event := range allEvents {
		for _, to := range allStates {
			if IsLegalTransition(StateRevoked, event, to) {
				t.Fatalf("StateRevoked must be strictly terminal; allowed transition on event %s to %s", event, to)
			}
		}
	}
}

func TestAdmission_ExpiredState_CannotBecomeAdmitted(t *testing.T) {
	for _, event := range allEvents {
		if IsLegalTransition(StateExpired, event, StateAdmitted) {
			t.Fatalf("StateExpired must not transition directly to StateAdmitted via %s", event)
		}
	}
}

func TestAdmission_WaitRoom_ProofOfPatience_Invariants15_16(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = true

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// 1. Initial request from new client
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	dec, err := engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if dec.Allowed {
		t.Errorf("new client should not be allowed during wait time")
	}
	if dec.State != StateWaiting {
		t.Errorf("expected StateWaiting, got %s", dec.State)
	}
	if dec.RetryAfter != 5*time.Second {
		t.Errorf("expected RetryAfter 5s, got %v", dec.RetryAfter)
	}
	if !errors.Is(dec.Error, ErrWaitTimeNotElapsed) {
		t.Errorf("expected ErrWaitTimeNotElapsed, got %v", dec.Error)
	}

	// 2. Client returns at t = 1s (premature request: Invariant 15)
	clock.Advance(1 * time.Second)
	dec, err = engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("Evaluate at 1s failed: %v", err)
	}
	if dec.Allowed {
		t.Errorf("client must not be allowed at t=1s")
	}
	if dec.State != StateWaiting {
		t.Errorf("expected StateWaiting, got %s", dec.State)
	}
	if dec.RetryAfter != 4*time.Second {
		t.Errorf("expected RetryAfter 4s at t=1s, got %v", dec.RetryAfter)
	}

	// 3. Client returns at t = 3s (still premature)
	clock.Advance(2 * time.Second)
	dec, err = engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("Evaluate at 3s failed: %v", err)
	}
	if dec.Allowed {
		t.Errorf("client must not be allowed at t=3s")
	}
	if dec.State != StateWaiting {
		t.Errorf("expected StateWaiting, got %s", dec.State)
	}
	if dec.RetryAfter != 2*time.Second {
		t.Errorf("expected RetryAfter 2s at t=3s, got %v", dec.RetryAfter)
	}

	// 4. Client returns at t = 5.1s (wait time elapsed!)
	clock.Advance(2100 * time.Millisecond)
	dec, err = engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("Evaluate at 5.1s failed: %v", err)
	}
	if dec.Allowed {
		t.Errorf("client must complete CAPTCHA before being allowed")
	}
	if dec.State != StateChallengeRequired {
		t.Errorf("expected StateChallengeRequired after wait elapsed, got %s", dec.State)
	}
}

func TestAdmission_WaitRoom_WithoutCaptcha_TransitionsToAdmitted(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 3 * time.Second
	cfg.Captcha.Enabled = false // CAPTCHA disabled

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	dec, _ := engine.Evaluate(ctx, sess)
	if dec.Allowed || dec.State != StateWaiting {
		t.Fatalf("expected StateWaiting initially, got %s", dec.State)
	}

	// Advance past wait time
	clock.Advance(4 * time.Second)
	dec, err = engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("client should be allowed when CAPTCHA is disabled and wait time elapsed")
	}
	if dec.State != StateAdmitted {
		t.Errorf("expected StateAdmitted, got %s", dec.State)
	}
}

func TestAdmission_DirectAdmission_NoWaitRoom_NoCaptcha(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	dec, err := engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("client should be admitted directly when friction disabled")
	}
	if dec.State != StateAdmitted {
		t.Errorf("expected StateAdmitted, got %s", dec.State)
	}
}

func TestAdmission_Evaluate_RevokedAndExpired(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// 1. Revoked session (Invariant 5)
	sessRevoked, _ := NewSession(clock.Now(), 5)
	sessRevoked.State = StateRevoked
	dec, err := engine.Evaluate(ctx, sessRevoked)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Allowed {
		t.Errorf("revoked session must never be allowed")
	}
	if dec.State != StateRevoked {
		t.Errorf("expected StateRevoked, got %s", dec.State)
	}
	if !errors.Is(dec.Error, ErrSessionRevoked) {
		t.Errorf("expected ErrSessionRevoked, got %v", dec.Error)
	}

	// 2. Expired session (Invariant 4)
	sessExpired, _ := NewSession(clock.Now(), 5)
	sessExpired.State = StateAdmitted
	sessExpired.ExpiresAt = clock.Now().Add(-1 * time.Hour)
	dec, err = engine.Evaluate(ctx, sessExpired)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec.Allowed {
		t.Errorf("expired session must not be allowed")
	}
	if dec.State != StateExpired {
		t.Errorf("expected StateExpired, got %s", dec.State)
	}
	if !errors.Is(dec.Error, ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", dec.Error)
	}

	// 3. Nil session
	decNil, err := engine.Evaluate(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error on nil session: %v", err)
	}
	if decNil.Allowed || !errors.Is(decNil.Error, ErrInvalidSession) {
		t.Errorf("expected ErrInvalidSession on nil session, got %+v", decNil)
	}
}

func TestAdmission_ConcurrentWaitElapsed_Deterministic(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = true

	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Initialize into WAITING
	dec, err := engine.Evaluate(ctx, sess)
	if err != nil || dec.State != StateWaiting {
		t.Fatalf("failed to initialize session to WAITING: %v", err)
	}

	// Advance clock past WaitTime
	clock.Advance(6 * time.Second)

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	decisions := make([]AdmissionDecision, concurrency)
	errorsList := make([]error, concurrency)
	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-startSignal

			dec, err := engine.Evaluate(ctx, sess)
			decisions[idx] = dec
			errorsList[idx] = err
		}()
	}

	close(startSignal) // Launch all 50 concurrent Evaluate calls simultaneously
	wg.Wait()

	// Verify deterministic state across all 50 concurrent calls
	for i := 0; i < concurrency; i++ {
		if errorsList[i] != nil {
			t.Errorf("goroutine #%d failed: %v", i, errorsList[i])
		}
		if decisions[i].Allowed {
			t.Errorf("goroutine #%d returned allowed=true before solving challenge", i)
		}
		if decisions[i].State != StateChallengeRequired {
			t.Errorf("goroutine #%d returned unexpected state: %s", i, decisions[i].State)
		}
	}

	// Verify final store state
	loaded, err := GetSession(ctx, memStore, sess.SessionID)
	if err != nil {
		t.Fatalf("failed to get session from store: %v", err)
	}
	if loaded.State != StateChallengeRequired {
		t.Errorf("store session state expected StateChallengeRequired, got %s", loaded.State)
	}
}

func TestAdmission_Transition_Concurrency(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	sess.State = StateChallengeRequired
	if err := SaveSession(ctx, memStore, sess, 1*time.Hour); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	const concurrency = 20
	var wg sync.WaitGroup
	wg.Add(concurrency)

	startSignal := make(chan struct{})
	errorsList := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-startSignal

			_, err := engine.Transition(ctx, sess.SessionID, EventChallengeSolved, StateAdmitted)
			errorsList[idx] = err
		}()
	}

	close(startSignal)
	wg.Wait()

	for i, err := range errorsList {
		if err != nil {
			t.Errorf("goroutine #%d encountered error in transition: %v", i, err)
		}
	}

	loaded, err := GetSession(ctx, memStore, sess.SessionID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if loaded.State != StateAdmitted {
		t.Errorf("expected final state StateAdmitted, got %s", loaded.State)
	}
}
