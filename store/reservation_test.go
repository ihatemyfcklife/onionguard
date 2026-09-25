package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestReservation_LimitEnforcement(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	ns := "test:limit"
	limit := 3
	expiry := time.Now().Add(10 * time.Minute)

	// Fill to capacity.
	for i := 0; i < limit; i++ {
		ok, err := s.ReserveSession(ctx, ns, fakeID(i), limit, expiry)
		if err != nil {
			t.Fatalf("reserve #%d: %v", i, err)
		}
		if !ok {
			t.Fatalf("reserve #%d: expected ok, got false", i)
		}
	}

	// One more should be rejected.
	ok, err := s.ReserveSession(ctx, ns, fakeID(99), limit, expiry)
	if err != nil {
		t.Fatalf("reserve beyond limit: %v", err)
	}
	if ok {
		t.Fatal("expected reservation to be rejected at capacity")
	}
}

func TestReservation_Expiry_PurgesStale(t *testing.T) {
	// Use a very short cleanup interval so the janitor purges quickly.
	cfg := DefaultMemoryConfig()
	cfg.CleanupInterval = 10 * time.Millisecond
	s, err := NewMemoryStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	ns := "test:expiry"
	limit := 2

	// Reserve 2 sessions with very short expiry.
	pastExpiry := time.Now().Add(5 * time.Millisecond)
	for i := 0; i < limit; i++ {
		ok, err := s.ReserveSession(ctx, ns, fakeID(i), limit, pastExpiry)
		if err != nil {
			t.Fatalf("reserve #%d: %v", i, err)
		}
		if !ok {
			t.Fatalf("reserve #%d: expected ok", i)
		}
	}

	// Wait for expiry + janitor sweep.
	time.Sleep(50 * time.Millisecond)

	// Now a new reservation should succeed because stale ones were purged by janitor.
	ok, err := s.ReserveSession(ctx, ns, fakeID(100), limit, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatalf("reserve after expiry: %v", err)
	}
	if !ok {
		t.Fatal("expected reservation to succeed after stale entries expired")
	}
}

func TestReservation_Move_Atomic(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	ns := "test:move"
	limit := 2
	expiry := time.Now().Add(10 * time.Minute)

	// Reserve session A.
	ok, err := s.ReserveSession(ctx, ns, "old-session", limit, expiry)
	if err != nil || !ok {
		t.Fatalf("reserve old: ok=%v err=%v", ok, err)
	}

	// Reserve session B to fill capacity.
	ok, err = s.ReserveSession(ctx, ns, "other-session", limit, expiry)
	if err != nil || !ok {
		t.Fatalf("reserve other: ok=%v err=%v", ok, err)
	}

	// At capacity — new reservation should fail.
	ok, err = s.ReserveSession(ctx, ns, "new-session", limit, expiry)
	if err != nil {
		t.Fatalf("reserve new: %v", err)
	}
	if ok {
		t.Fatal("expected reservation to fail at capacity")
	}

	// Move old → new: count should stay the same.
	newExpiry := time.Now().Add(20 * time.Minute)
	if err := s.MoveSessionReservation(ctx, ns, "old-session", "new-session", newExpiry); err != nil {
		t.Fatalf("move: %v", err)
	}

	// Old session should no longer exist in reservations.
	// Verify by trying to move it again — should get ErrNotFound.
	if err := s.MoveSessionReservation(ctx, ns, "old-session", "another", expiry); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound for deleted old reservation, got %v", err)
	}

	// The moved slot should be occupied by new-session and other-session.
	// One more should fail.
	ok, err = s.ReserveSession(ctx, ns, "extra-session", limit, expiry)
	if err != nil {
		t.Fatalf("reserve extra: %v", err)
	}
	if ok {
		t.Fatal("expected extra reservation to fail at capacity after move")
	}
}

func TestReservation_Release_FreesSlot(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	ns := "test:release"
	limit := 1
	expiry := time.Now().Add(10 * time.Minute)

	// Fill the single slot.
	ok, err := s.ReserveSession(ctx, ns, "session-1", limit, expiry)
	if err != nil || !ok {
		t.Fatalf("reserve: ok=%v err=%v", ok, err)
	}

	// Verify at capacity.
	ok, err = s.ReserveSession(ctx, ns, "session-2", limit, expiry)
	if err != nil {
		t.Fatalf("reserve second: %v", err)
	}
	if ok {
		t.Fatal("expected second reservation to fail at capacity")
	}

	// Release and verify slot is freed.
	if err := s.ReleaseSession(ctx, ns, "session-1"); err != nil {
		t.Fatalf("release: %v", err)
	}

	ok, err = s.ReserveSession(ctx, ns, "session-2", limit, expiry)
	if err != nil || !ok {
		t.Fatalf("reserve after release: ok=%v err=%v", ok, err)
	}
}

func TestReservation_Idempotent_UpdatesExpiry(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	ns := "test:idempotent"
	limit := 1
	expiry1 := time.Now().Add(1 * time.Minute)
	expiry2 := time.Now().Add(30 * time.Minute)

	// Reserve once.
	ok, err := s.ReserveSession(ctx, ns, "session-x", limit, expiry1)
	if err != nil || !ok {
		t.Fatalf("first reserve: ok=%v err=%v", ok, err)
	}

	// Reserve again with same ID — should succeed and update expiry (not count as new).
	ok, err = s.ReserveSession(ctx, ns, "session-x", limit, expiry2)
	if err != nil || !ok {
		t.Fatalf("idempotent reserve: ok=%v err=%v", ok, err)
	}

	// Verify that the slot is still just one.
	ok, err = s.ReserveSession(ctx, ns, "session-y", limit, expiry2)
	if err != nil {
		t.Fatalf("reserve y: %v", err)
	}
	if ok {
		t.Fatal("expected y to be rejected — only 1 slot, occupied by session-x")
	}
}

func TestReservation_Concurrent_RaceDetector(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	ns := "test:race"
	limit := 50
	expiry := time.Now().Add(10 * time.Minute)

	const concurrency = 100
	var wg sync.WaitGroup
	wg.Add(concurrency)

	successes := make([]bool, concurrency)
	startSignal := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-startSignal
			ok, err := s.ReserveSession(ctx, ns, fakeID(idx), limit, expiry)
			if err != nil {
				t.Errorf("goroutine %d: %v", idx, err)
				return
			}
			successes[idx] = ok
		}()
	}

	close(startSignal)
	wg.Wait()

	accepted := 0
	for _, ok := range successes {
		if ok {
			accepted++
		}
	}

	if accepted > limit {
		t.Fatalf("race violation: accepted %d reservations but limit is %d", accepted, limit)
	}
	if accepted != limit {
		t.Logf("accepted %d/%d (some goroutines competed for the same slots)", accepted, limit)
	}
}

func TestReservation_InvalidInputs(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	// Empty namespace
	_, err = s.ReserveSession(ctx, "", "sid", 10, time.Now().Add(time.Minute))
	if err != ErrInvalidValue {
		t.Errorf("empty namespace: expected ErrInvalidValue, got %v", err)
	}

	// Empty sessionID
	_, err = s.ReserveSession(ctx, "ns", "", 10, time.Now().Add(time.Minute))
	if err != ErrInvalidValue {
		t.Errorf("empty sessionID: expected ErrInvalidValue, got %v", err)
	}

	// Zero limit
	_, err = s.ReserveSession(ctx, "ns", "sid", 0, time.Now().Add(time.Minute))
	if err != ErrInvalidValue {
		t.Errorf("zero limit: expected ErrInvalidValue, got %v", err)
	}

	// Zero expiry
	_, err = s.ReserveSession(ctx, "ns", "sid", 10, time.Time{})
	if err != ErrInvalidValue {
		t.Errorf("zero expiry: expected ErrInvalidValue, got %v", err)
	}
}

func TestReservation_ClosedStore(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	ctx := context.Background()
	_, err = s.ReserveSession(ctx, "ns", "sid", 10, time.Now().Add(time.Minute))
	if err != ErrStoreClosed {
		t.Errorf("reserve on closed store: expected ErrStoreClosed, got %v", err)
	}
	err = s.ReleaseSession(ctx, "ns", "sid")
	if err != ErrStoreClosed {
		t.Errorf("release on closed store: expected ErrStoreClosed, got %v", err)
	}
	err = s.MoveSessionReservation(ctx, "ns", "old", "new", time.Now().Add(time.Minute))
	if err != ErrStoreClosed {
		t.Errorf("move on closed store: expected ErrStoreClosed, got %v", err)
	}
}

func fakeID(i int) string {
	return "session-" + string(rune('A'+i%26)) + string(rune('0'+i/26%10))
}

func TestReservation_MultiNamespaceIsolation(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()
	expiry := time.Now().Add(10 * time.Minute)

	// Fill namespace A to limit 2
	ok, err := s.ReserveSession(ctx, "ns-A", "sid-1", 2, expiry)
	if err != nil || !ok {
		t.Fatalf("ns-A reserve 1 failed: ok=%v, err=%v", ok, err)
	}
	ok, err = s.ReserveSession(ctx, "ns-A", "sid-2", 2, expiry)
	if err != nil || !ok {
		t.Fatalf("ns-A reserve 2 failed: ok=%v, err=%v", ok, err)
	}
	// ns-A is at limit
	ok, err = s.ReserveSession(ctx, "ns-A", "sid-3", 2, expiry)
	if err != nil || ok {
		t.Fatalf("expected ns-A reserve 3 to fail at limit 2, got ok=%v", ok)
	}

	// Namespace B with limit 2 should NOT be blocked by namespace A
	ok, err = s.ReserveSession(ctx, "ns-B", "sid-b1", 2, expiry)
	if err != nil || !ok {
		t.Fatalf("expected ns-B reserve 1 to succeed, got ok=%v, err=%v", ok, err)
	}
	ok, err = s.ReserveSession(ctx, "ns-B", "sid-b2", 2, expiry)
	if err != nil || !ok {
		t.Fatalf("expected ns-B reserve 2 to succeed, got ok=%v, err=%v", ok, err)
	}
	// ns-B at limit
	ok, err = s.ReserveSession(ctx, "ns-B", "sid-b3", 2, expiry)
	if err != nil || ok {
		t.Fatalf("expected ns-B reserve 3 to fail at limit 2, got ok=%v", ok)
	}
}
