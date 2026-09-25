package onionguard

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"onionguard/store"
)

func TestSession_10000_EntropyAndCollision(t *testing.T) {
	const sampleCount = 10000
	seen := make(map[string]struct{}, sampleCount)
	charFreq := make(map[rune]int)
	totalChars := 0

	for i := 0; i < sampleCount; i++ {
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatalf("GenerateSessionID() failed at index %d: %v", i, err)
		}

		// 1. Validate length (Invariant 3: exactly 43 chars for 32 raw bytes base64 unpadded)
		if len(id) != SessionIDStringLen {
			t.Fatalf("expected length %d, got %d for token %q", SessionIDStringLen, len(id), id)
		}

		// 2. Validate format
		if err := ValidateSessionID(id); err != nil {
			t.Fatalf("ValidateSessionID() failed for %q: %v", id, err)
		}

		// 3. Collision check
		if _, exists := seen[id]; exists {
			t.Fatalf("cryptographic collision detected at sample %d: %q", i, id)
		}
		seen[id] = struct{}{}

		// 4. Character frequency counting for Shannon entropy
		for _, r := range id {
			charFreq[r]++
			totalChars++
		}
	}

	if len(seen) != sampleCount {
		t.Fatalf("expected %d unique session IDs, got %d", sampleCount, len(seen))
	}

	// 5. Calculate Shannon entropy H = -sum(p_i * log2(p_i))
	var entropy float64
	for _, count := range charFreq {
		p := float64(count) / float64(totalChars)
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	// Base64 alphabet has 64 symbols; theoretical maximum entropy is log2(64) = 6.0 bits/char.
	// We require H >= 5.95 bits/char to guarantee uniform randomness and high cryptographic entropy.
	const minRequiredEntropy = 5.95
	t.Logf("Calculated Shannon Entropy: %.4f bits/char across %d characters (min required: %.2f)",
		entropy, totalChars, minRequiredEntropy)

	if entropy < minRequiredEntropy {
		t.Fatalf("entropy too low: %.4f < %.2f bits/char", entropy, minRequiredEntropy)
	}
}

func TestSession_Validation(t *testing.T) {
	validID, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("failed to generate session ID: %v", err)
	}

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "Valid 43-char raw URL base64",
			id:      validID,
			wantErr: false,
		},
		{
			name:    "Empty string",
			id:      "",
			wantErr: true,
		},
		{
			name:    "Too short (42 chars)",
			id:      validID[:42],
			wantErr: true,
		},
		{
			name:    "Too long (44 chars)",
			id:      validID + "A",
			wantErr: true,
		},
		{
			name:    "Padded with = (standard base64 padding forbidden)",
			id:      validID[:42] + "=",
			wantErr: true,
		},
		{
			name:    "Standard Base64 with + and / forbidden (must be URL-safe - and _)",
			id:      "+++++++++++++++++++++++++++++++++++++++++++",
			wantErr: true,
		},
		{
			name:    "Contains spaces",
			id:      validID[:20] + " " + validID[21:],
			wantErr: true,
		},
		{
			name:    "Contains null byte",
			id:      validID[:20] + "\x00" + validID[21:],
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSessionID(tc.id)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for id %q, got nil", tc.id)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for id %q: %v", tc.id, err)
			}
		})
	}
}

func TestSession_Lifecycle_CRUD_Expiration_Revocation(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := NewTestClock(start)
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 5)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if sess.State != StateNew {
		t.Errorf("expected StateNew, got %s", sess.State)
	}
	if sess.RenewalCount != 0 {
		t.Errorf("expected RenewalCount 0, got %d", sess.RenewalCount)
	}

	// 1. Save and Get
	ttl := 1 * time.Hour
	sess.ExpiresAt = clock.Now().Add(ttl)
	if err := SaveSession(ctx, memStore, sess, ttl); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	loaded, err := GetSession(ctx, memStore, sess.SessionID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if loaded.SessionID != sess.SessionID {
		t.Errorf("loaded ID mismatch: %s != %s", loaded.SessionID, sess.SessionID)
	}
	if loaded.RenewalCount != sess.RenewalCount {
		t.Errorf("loaded RenewalCount mismatch")
	}

	// 2. Expiration check (Invariant 4)
	if loaded.IsExpired(clock.Now()) {
		t.Errorf("session should not be expired at start")
	}
	// Advance clock past expiration
	clock.Advance(2 * time.Hour)
	if !loaded.IsExpired(clock.Now()) {
		t.Errorf("session should be expired after 2 hours")
	}

	// Reset clock
	clock.Set(start)
	if loaded.IsExpired(clock.Now()) {
		t.Errorf("session should not be expired after resetting clock")
	}

	// 3. Revocation check (Invariant 5)
	if loaded.IsRevoked() {
		t.Errorf("session should not be revoked initially")
	}
	if err := RevokeSession(ctx, memStore, sess.SessionID, 10*time.Minute); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	revoked, err := GetSession(ctx, memStore, sess.SessionID)
	if err != nil {
		t.Fatalf("GetSession after revoke failed: %v", err)
	}
	if !revoked.IsRevoked() {
		t.Errorf("expected session to be revoked")
	}
	if revoked.State != StateRevoked {
		t.Errorf("expected StateRevoked, got %s", revoked.State)
	}

	// 4. Delete
	if err := DeleteSession(ctx, memStore, sess.SessionID); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	_, err = GetSession(ctx, memStore, sess.SessionID)
	if err == nil || !errors.Is(err, ErrInvalidSession) {
		t.Errorf("expected ErrInvalidSession after delete, got %v", err)
	}
}

func TestSession_String_Redaction_Invariant1_24(t *testing.T) {
	sess, err := NewSession(time.Now(), 10)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	rawID := sess.SessionID
	masked := MaskSessionID(rawID)

	// Invariant 24: Plaintext session IDs must NEVER appear in String, GoString, %v, %+v
	formats := []string{
		sess.String(),
		sess.GoString(),
		fmt.Sprintf("%v", sess),
		fmt.Sprintf("%+v", sess),
		fmt.Sprintf("%#v", sess),
	}

	for i, f := range formats {
		if strings.Contains(f, rawID) {
			t.Errorf("format #%d leaked raw session ID %q: %s", i, rawID, f)
		}
		if !strings.Contains(f, masked) {
			t.Errorf("format #%d missing masked ID %q: %s", i, masked, f)
		}
	}

	if MaskSessionID("") != "[NONE]" {
		t.Errorf("expected [NONE] for empty session ID mask, got %q", MaskSessionID(""))
	}
}

func TestSession_AtomicRotation(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	ctx := context.Background()

	// 1. Normal rotation of admitted session
	sess, err := NewSession(clock.Now(), 3)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	if err := SaveSession(ctx, memStore, sess, 1*time.Hour); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	oldID := sess.SessionID
	newSess, err := RotateSession(ctx, memStore, oldID, 1*time.Hour, clock)
	if err != nil {
		t.Fatalf("RotateSession failed: %v", err)
	}

	// Invariant 6: Old session ID must be deleted immediately
	if _, err := GetSession(ctx, memStore, oldID); err == nil || !errors.Is(err, ErrInvalidSession) {
		t.Errorf("expected old session ID to be non-existent after rotation, got %v", err)
	}

	if newSess.SessionID == oldID {
		t.Errorf("new session ID should be different from old session ID")
	}
	if newSess.RenewalCount != 1 {
		t.Errorf("expected RenewalCount 1, got %d", newSess.RenewalCount)
	}
	if newSess.State != StateAdmitted {
		t.Errorf("expected new session to be in StateAdmitted, got %s", newSess.State)
	}

	// 2. Rotate until MaxRenewals is reached
	curID := newSess.SessionID
	for i := 2; i <= 3; i++ {
		rotated, err := RotateSession(ctx, memStore, curID, 1*time.Hour, clock)
		if err != nil {
			t.Fatalf("rotation #%d failed: %v", i, err)
		}
		if rotated.RenewalCount != i {
			t.Errorf("expected renewal count %d, got %d", i, rotated.RenewalCount)
		}
		curID = rotated.SessionID
	}

	// 3. Next rotation should exceed MaxRenewals (RenewalCount == 3 >= MaxRenewals 3)
	_, err = RotateSession(ctx, memStore, curID, 1*time.Hour, clock)
	if err == nil || !errors.Is(err, ErrRenewalLimitReached) {
		t.Fatalf("expected ErrRenewalLimitReached when MaxRenewals exceeded, got %v", err)
	}

	// 4. Rotating expired session
	sessExpired, _ := NewSession(clock.Now(), 5)
	sessExpired.State = StateAdmitted
	sessExpired.ExpiresAt = clock.Now().Add(-10 * time.Minute)
	_ = SaveSession(ctx, memStore, sessExpired, 1*time.Hour)

	_, err = RotateSession(ctx, memStore, sessExpired.SessionID, 1*time.Hour, clock)
	if err == nil || !errors.Is(err, ErrSessionExpired) {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}

	// 5. Rotating revoked session
	sessRevoked, _ := NewSession(clock.Now(), 5)
	sessRevoked.State = StateRevoked
	_ = SaveSession(ctx, memStore, sessRevoked, 1*time.Hour)

	_, err = RotateSession(ctx, memStore, sessRevoked.SessionID, 1*time.Hour, clock)
	if err == nil || !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("expected ErrSessionRevoked, got %v", err)
	}

	// 6. Rotating unadmitted session (StateWaiting)
	sessWaiting, _ := NewSession(clock.Now(), 5)
	sessWaiting.State = StateWaiting
	_ = SaveSession(ctx, memStore, sessWaiting, 1*time.Hour)

	_, err = RotateSession(ctx, memStore, sessWaiting.SessionID, 1*time.Hour, clock)
	if err == nil || !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("expected ErrInvalidTransition for unadmitted session, got %v", err)
	}
}

func TestSession_Rotation_Race_Under_RaceDetector(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer memStore.Close()

	clock := RealClock{}
	ctx := context.Background()

	sess, err := NewSession(clock.Now(), 10)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = clock.Now().Add(1 * time.Hour)
	if err := SaveSession(ctx, memStore, sess, 1*time.Hour); err != nil {
		t.Fatalf("SaveSession failed: %v", err)
	}

	const concurrency = 50
	var wg sync.WaitGroup
	wg.Add(concurrency)

	var successCount int64
	var failureCount int64
	var succeededID string
	var idMu sync.Mutex

	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			<-startSignal // Synchronize all goroutines to launch simultaneously

			newSess, err := RotateSession(ctx, memStore, sess.SessionID, 1*time.Hour, clock)
			if err == nil {
				atomic.AddInt64(&successCount, 1)
				idMu.Lock()
				succeededID = newSess.SessionID
				idMu.Unlock()
			} else {
				atomic.AddInt64(&failureCount, 1)
			}
		}()
	}

	close(startSignal) // Release all 50 goroutines simultaneously
	wg.Wait()

	// Invariants 6 & 8: Under concurrent rotation races, EXACTLY ONE goroutine must succeed
	if successCount != 1 {
		t.Fatalf("concurrency hazard: expected exactly 1 successful rotation, got %d", successCount)
	}
	if failureCount != concurrency-1 {
		t.Fatalf("expected %d failed rotations, got %d", concurrency-1, failureCount)
	}

	// Verify that the succeeded session exists in the store
	idMu.Lock()
	validNewID := succeededID
	idMu.Unlock()

	loaded, err := GetSession(ctx, memStore, validNewID)
	if err != nil {
		t.Fatalf("failed to get newly rotated session: %v", err)
	}
	if loaded.RenewalCount != 1 {
		t.Errorf("expected RenewalCount 1, got %d", loaded.RenewalCount)
	}

	// Verify that the old session ID is completely gone
	if _, err := GetSession(ctx, memStore, sess.SessionID); err == nil || !errors.Is(err, ErrInvalidSession) {
		t.Errorf("expected old session ID to be non-existent, got %v", err)
	}
}
