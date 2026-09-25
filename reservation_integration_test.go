package onionguard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

// TestReservation_RevokeSession_ReleasesSlot verifies that RevokeSession
// immediately frees the reservation slot so new sessions can be admitted.
func TestReservation_RevokeSession_ReleasesSlot(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.MaxConcurrentSessions = 2
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// Admit 2 sessions to fill capacity.
	sessions := make([]*Session, 2)
	for i := range sessions {
		sess, err := NewSession(clock.Now(), 5)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := engine.Evaluate(ctx, sess)
		if err != nil {
			t.Fatalf("session #%d evaluate: %v", i, err)
		}
		if !dec.Allowed {
			t.Fatalf("session #%d should be allowed", i)
		}
		sessions[i] = dec.Session
	}

	// Third session should be rejected — capacity full.
	sessBlocked, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := engine.Evaluate(ctx, sessBlocked)
	if err == nil || !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected ErrCapacityExceeded, got dec=%+v err=%v", dec, err)
	}

	// Revoke session #0.
	if err := RevokeSession(ctx, memStore, sessions[0].SessionID, 5*time.Minute); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Now session #3 should be admitted — slot freed.
	sessNew, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err = engine.Evaluate(ctx, sessNew)
	if err != nil {
		t.Fatalf("evaluate after revoke: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("expected new session to be admitted after revoke, got state %s, err %v", dec.State, dec.Error)
	}
}

// TestReservation_RotateSession_TransfersSlot verifies that RotateSession
// atomically transfers the reservation from old to new session ID without
// consuming an additional slot.
func TestReservation_RotateSession_TransfersSlot(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.MaxConcurrentSessions = 2
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// Admit 2 sessions to fill capacity.
	sess1, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := engine.Evaluate(ctx, sess1)
	if err != nil || !dec.Allowed {
		t.Fatalf("sess1: allowed=%v err=%v", dec.Allowed, err)
	}
	sess1 = dec.Session

	sess2, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err = engine.Evaluate(ctx, sess2)
	if err != nil || !dec.Allowed {
		t.Fatalf("sess2: allowed=%v err=%v", dec.Allowed, err)
	}

	// Rotate session 1 — should NOT increase count.
	rotated, err := RotateSession(ctx, memStore, sess1.SessionID, cfg.SessionTTL, clock)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.SessionID == sess1.SessionID {
		t.Fatal("rotated session should have a new ID")
	}

	// After rotation, capacity is still full (2 slots occupied: rotated + sess2).
	// A third session should still be blocked.
	sess3, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err = engine.Evaluate(ctx, sess3)
	if err == nil || !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected capacity exceeded after rotation, got dec=%+v err=%v", dec, err)
	}
}

// TestReservation_Transition_RevokeFrees verifies that the Transition() method
// releases the reservation when transitioning to StateRevoked.
func TestReservation_Transition_RevokeFrees(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.MaxConcurrentSessions = 1
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// Admit one session.
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := engine.Evaluate(ctx, sess)
	if err != nil || !dec.Allowed {
		t.Fatalf("evaluate: allowed=%v err=%v", dec.Allowed, err)
	}

	// Capacity full — second blocked.
	sess2, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Evaluate(ctx, sess2)
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected capacity exceeded, got %v", err)
	}

	// Transition to revoked via admission engine.
	_, err = engine.Transition(ctx, dec.Session.SessionID, EventRevoke, StateRevoked)
	if err != nil {
		t.Fatalf("transition revoke: %v", err)
	}

	// Slot freed — new session should be admitted.
	sess3, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err = engine.Evaluate(ctx, sess3)
	if err != nil {
		t.Fatalf("evaluate after transition revoke: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("expected admission after transition-revoke freed slot, got state=%s", dec.State)
	}
}

// TestReservation_Transition_ExpiredFrees verifies that transitioning to
// StateExpired releases the reservation slot.
func TestReservation_Transition_ExpiredFrees(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.MaxConcurrentSessions = 1
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := engine.Evaluate(ctx, sess)
	if err != nil || !dec.Allowed {
		t.Fatalf("initial: allowed=%v err=%v", dec.Allowed, err)
	}

	// Transition to expired.
	_, err = engine.Transition(ctx, dec.Session.SessionID, EventExpire, StateExpired)
	if err != nil {
		t.Fatalf("transition expire: %v", err)
	}

	// Slot freed.
	sessNew, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err = engine.Evaluate(ctx, sessNew)
	if err != nil {
		t.Fatalf("evaluate after expire: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("expected admission after expired freed slot, got state=%s", dec.State)
	}
}

// TestReservation_WaitElapsed_RenewsTTL verifies that handleWaitElapsed
// renews the reservation TTL when transitioning to StateChallengeRequired.
func TestReservation_WaitElapsed_RenewsTTL(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = true
	cfg.WaitRoom.WaitTime = 2 * time.Second
	cfg.Captcha.Enabled = true
	cfg.MaxConcurrentSessions = 1
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// New client enters wait room — reservation created.
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("first evaluate: %v", err)
	}
	if dec.State != StateWaiting {
		t.Fatalf("expected StateWaiting, got %s", dec.State)
	}

	// Advance past wait time.
	clock.Advance(3 * time.Second)

	// Evaluate again — should transition to CHALLENGE_REQUIRED and renew reservation.
	dec, err = engine.Evaluate(ctx, sess)
	if err != nil {
		t.Fatalf("second evaluate: %v", err)
	}
	if dec.State != StateChallengeRequired {
		t.Fatalf("expected StateChallengeRequired, got %s", dec.State)
	}

	// The reservation should still be active — new session should be blocked.
	sess2, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Evaluate(ctx, sess2)
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected capacity exceeded (reservation still held), got %v", err)
	}
}

// TestReservation_FullCycle_CreateRotateRevokeReadmit tests the complete lifecycle:
// create → rotate → revoke → new admit.
func TestReservation_FullCycle_CreateRotateRevokeReadmit(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.MaxConcurrentSessions = 1
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// Step 1: Admit a session.
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := engine.Evaluate(ctx, sess)
	if err != nil || !dec.Allowed {
		t.Fatalf("step 1: allowed=%v err=%v", dec.Allowed, err)
	}
	originalID := dec.Session.SessionID

	// Step 2: Rotate.
	rotated, err := RotateSession(ctx, memStore, originalID, cfg.SessionTTL, clock)
	if err != nil {
		t.Fatalf("step 2 rotate: %v", err)
	}

	// Still at capacity (1 slot, now held by rotated).
	blocked, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Evaluate(ctx, blocked)
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("step 2: expected capacity exceeded, got %v", err)
	}

	// Step 3: Revoke the rotated session.
	if err := RevokeSession(ctx, memStore, rotated.SessionID, 5*time.Minute); err != nil {
		t.Fatalf("step 3 revoke: %v", err)
	}

	// Step 4: New session should now be admitted.
	newSess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	dec, err = engine.Evaluate(ctx, newSess)
	if err != nil {
		t.Fatalf("step 4: %v", err)
	}
	if !dec.Allowed {
		t.Errorf("step 4: expected admission after full cycle, got state=%s err=%v", dec.State, dec.Error)
	}
}

// TestReservation_Transition_AdmittedRenews verifies that transitioning
// to StateAdmitted (e.g. ChallengeSolved) renews the reservation TTL.
func TestReservation_Transition_AdmittedRenews(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = false
	cfg.MaxConcurrentSessions = 1
	engine := NewAdmissionEngine(cfg, memStore, clock)
	ctx := context.Background()

	// Create a session in CHALLENGE_REQUIRED state manually.
	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	sess.State = StateChallengeRequired
	sess.ExpiresAt = clock.Now().Add(10 * time.Minute)
	if err := SaveSession(ctx, memStore, sess, 10*time.Minute); err != nil {
		t.Fatal(err)
	}

	// Reserve its slot manually.
	reservations := memStore
	ok, err := reservations.ReserveSession(ctx, "admission:session-capacity", sess.SessionID, 1, clock.Now().Add(10*time.Minute))
	if err != nil || !ok {
		t.Fatalf("manual reserve: ok=%v err=%v", ok, err)
	}

	// Transition to ADMITTED — should renew reservation.
	result, err := engine.Transition(ctx, sess.SessionID, EventChallengeSolved, StateAdmitted)
	if err != nil {
		t.Fatalf("transition: %v", err)
	}
	if result.State != StateAdmitted {
		t.Fatalf("expected StateAdmitted, got %s", result.State)
	}

	// Reservation should still be held — new session blocked.
	sess2, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.Evaluate(ctx, sess2)
	if !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("expected capacity exceeded (reservation renewed), got %v", err)
	}
}
