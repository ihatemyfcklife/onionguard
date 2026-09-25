package onionguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

// TestAdversarial_RotationResurrection_50ConcurrentRequests tests Task 1:
// 50+ goroutines making requests using the old session ID while rotation executes concurrently.
// It verifies:
// 1. Zero duplicate sessions
// 2. Old session ID is invalid
// 3. Exactly one new session token survives
func TestAdversarial_RotationResurrection_50ConcurrentRequests(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	cfg := DefaultConfig()
	cfg.SessionTTL = 1 * time.Hour
	engine := NewAdmissionEngine(cfg, memStore, clock)
	resolver := NewIdentityResolver(cfg, memStore, clock, nil, nil)
	ctx := context.Background()

	// 1. Create an admitted session
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(cfg.SessionTTL)
	if err := SaveSession(ctx, memStore, sess, cfg.SessionTTL); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	oldID := sess.SessionID

	const concurrency = 60
	var wg sync.WaitGroup
	wg.Add(concurrency + 1) // 60 requests + 1 rotation

	startSignal := make(chan struct{})

	var rotationSuccess int64
	var rotatedSessionID string
	var rotMu sync.Mutex

	// Goroutine performing rotation
	go func() {
		defer wg.Done()
		<-startSignal

		time.Sleep(50 * time.Microsecond)
		newSess, rotErr := RotateSession(ctx, memStore, oldID, cfg.SessionTTL, clock)
		if rotErr == nil {
			atomic.AddInt64(&rotationSuccess, 1)
			rotMu.Lock()
			rotatedSessionID = newSess.SessionID
			rotMu.Unlock()
		}
	}()

	// 60 goroutines making requests using oldID
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-startSignal

			// Request with old session cookie
			req := httptest.NewRequest("GET", "/test", nil)
			req.AddCookie(&http.Cookie{
				Name:  cfg.SessionCookieName,
				Value: oldID,
			})

			// 1. Resolve identity
			ci, resErr := resolver.Resolve(req)
			if resErr == nil && ci.Kind == IdentityAnonymous {
				// 2. Fetch session and evaluate admission
				s, getErr := GetSession(ctx, memStore, ci.SessionID)
				if getErr == nil && s != nil {
					_, _ = engine.Evaluate(ctx, s)
				}
			}
		}()
	}

	close(startSignal)
	wg.Wait()

	if rotationSuccess != 1 {
		t.Fatalf("expected rotation to succeed, got successCount=%d", rotationSuccess)
	}

	rotMu.Lock()
	newID := rotatedSessionID
	rotMu.Unlock()

	// Invariant Check 1: Old session ID MUST be invalid in store
	loadedOld, err := GetSession(ctx, memStore, oldID)
	if err == nil {
		t.Errorf("CRITICAL BUG / RESURRECTION: Old session ID %q is still present and valid in store! Loaded: %+v",
			oldID, loadedOld)
	}
	if !errors.Is(err, ErrInvalidSession) {
		t.Errorf("expected ErrInvalidSession for old session ID, got: %v", err)
	}

	// Invariant Check 2: Exactly one new session token survives
	loadedNew, err := GetSession(ctx, memStore, newID)
	if err != nil {
		t.Fatalf("failed to retrieve newly rotated session %q: %v", newID, err)
	}
	if loadedNew.SessionID != newID {
		t.Fatalf("retrieved session ID mismatch: expected %q, got %q", newID, loadedNew.SessionID)
	}
	if loadedNew.RenewalCount != 1 {
		t.Fatalf("expected RenewalCount 1, got %d", loadedNew.RenewalCount)
	}
}

// TestAdversarial_SessionLocking_BypassedWhenLockHeld tests Task 2:
// Verifies whether Session Locking actually protects critical sections when lock acquisition fails or lock is held.
func TestAdversarial_SessionLocking_BypassedWhenLockHeld(t *testing.T) {
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
	sess.State = StateWaiting
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	if err := SaveSession(ctx, memStore, sess, 1*time.Hour); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	// Another process acquires the distributed lock for this session
	lockKey := "lock:" + SessionKey(sess.SessionID)
	acquired, err := memStore.SetNX(ctx, lockKey, []byte("holder"), 10*time.Second)
	if err != nil || !acquired {
		t.Fatalf("failed to simulate external lock hold: acquired=%v, err=%v", acquired, err)
	}

	// Now attempt Transition while lock is held by another process
	res, err := engine.Transition(ctx, sess.SessionID, EventWaitElapsed, StateChallengeRequired)

	// Since the lock was NOT acquired by engine.Transition, it MUST NOT execute the transition!
	// It should return an error indicating lock could not be acquired.
	if err == nil {
		t.Fatalf("CRITICAL BUG / LOCK BYPASS: Transition succeeded without acquiring lock! State changed to %s", res.State)
	}
}

// TestAdversarial_HandleWaitElapsed_BypassedWhenLockHeld tests Task 2:
// Verifies whether handleWaitElapsed executes without the lock when lock is held.
func TestAdversarial_HandleWaitElapsed_BypassedWhenLockHeld(t *testing.T) {
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
	sess.State = StateWaiting
	_ = SaveSession(ctx, memStore, sess, 1*time.Hour)

	// Advance time past WaitTime
	clock.Advance(6 * time.Second)

	// Another process holds the lock
	lockKey := "lock:" + SessionKey(sess.SessionID)
	acquired, err := memStore.SetNX(ctx, lockKey, []byte("holder"), 10*time.Second)
	if err != nil || !acquired {
		t.Fatalf("failed to acquire lock: %v", err)
	}

	// Evaluate when wait elapsed
	dec, err := engine.Evaluate(ctx, sess)

	// Since lock could not be acquired, it should NOT have transitioned to CHALLENGE_REQUIRED
	if dec.State == StateChallengeRequired {
		t.Fatalf("CRITICAL BUG / LOCK BYPASS: handleWaitElapsed modified session state to %s without holding lock!", dec.State)
	}
	if err == nil {
		t.Fatalf("expected error due to unacquired lock, got nil")
	}
}

// TestAdversarial_ConcurrentConflictingTransitions tests Task 2:
// One goroutine revokes the session while another goroutine attempts to rotate it.
// Revocation must NEVER be undone or bypassed!
func TestAdversarial_ConcurrentConflictingTransitions(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
		if err != nil {
			t.Fatalf("failed to create memory store: %v", err)
		}

		clock := RealClock{}
		cfg := DefaultConfig()
		engine := NewAdmissionEngine(cfg, memStore, clock)
		ctx := context.Background()

		sess, err := NewSession(clock.Now(), 5)
		if err != nil {
			t.Fatalf("NewSession failed: %v", err)
		}
		sess.State = StateAdmitted
		sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
		_ = SaveSession(ctx, memStore, sess, 1*time.Hour)

		sessionID := sess.SessionID

		var wg sync.WaitGroup
		wg.Add(2)

		startSignal := make(chan struct{})
		var revokeErr error
		var rotateResult *Session
		var rotateErr error

		// Goroutine 1: Revoke session (terminal state)
		go func() {
			defer wg.Done()
			<-startSignal
			_, revokeErr = engine.Transition(ctx, sessionID, EventRevoke, StateRevoked)
		}()

		// Goroutine 2: Rotate session
		go func() {
			defer wg.Done()
			<-startSignal
			rotateResult, rotateErr = RotateSession(ctx, memStore, sessionID, 1*time.Hour, clock)
		}()

		close(startSignal)
		wg.Wait()

		// If revoke succeeded:
		if revokeErr == nil {
			// If rotate ALSO succeeded, the revoked client was issued a brand-new valid active session!
			if rotateErr == nil && rotateResult != nil {
				// Check if the rotated session is admitted in store
				loaded, err := GetSession(ctx, memStore, rotateResult.SessionID)
				if err == nil && loaded.State == StateAdmitted {
					t.Fatalf("[iter %d] CRITICAL SECURITY BUG: Revoked session was rotated into new active admitted session %s! Revocation bypassed!",
						iter, MaskSessionID(rotateResult.SessionID))
				}
			}
		}

		_ = memStore.Close()
	}
}

// TestAdversarial_Evaluate_SharedSessionPointer_DataRace tests Task 3:
// Verifies whether passing the same *Session pointer across concurrent Evaluate calls causes data races.
func TestAdversarial_Evaluate_SharedSessionPointer_DataRace(t *testing.T) {
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
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	_ = SaveSession(ctx, memStore, sess, 1*time.Hour)

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-startSignal

			// Concurrent call to Evaluate using the shared *Session pointer
			_, _ = engine.Evaluate(ctx, sess)
		}()
	}

	close(startSignal)
	wg.Wait()
}
