package onionguard

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

func TestCircuitBreaker_TripsOpenOnThreshold(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 3,
		CoolDown:         5 * time.Second,
	}

	var stateChanges []string
	cb := NewCircuitBreaker(cfg, clock, func(from, to CircuitState) {
		stateChanges = append(stateChanges, from.String()+"->"+to.String())
	})

	if cb.State() != CircuitClosed {
		t.Fatalf("expected initial state CLOSED, got %s", cb.State())
	}

	// 1. Normal errors (e.g. ErrNotFound) must NOT trip breaker
	for i := 0; i < 10; i++ {
		done, err := cb.Allow()
		if err != nil {
			t.Fatalf("unexpected allow error: %v", err)
		}
		done(store.ErrNotFound)
	}
	if cb.State() != CircuitClosed {
		t.Fatalf("expected state CLOSED after ErrNotFound, got %s", cb.State())
	}

	// 2. Report 2 infrastructure failures (below threshold of 3)
	for i := 0; i < 2; i++ {
		done, err := cb.Allow()
		if err != nil {
			t.Fatalf("unexpected allow error: %v", err)
		}
		done(store.ErrStoreUnavailable)
	}
	if cb.State() != CircuitClosed {
		t.Fatalf("expected state still CLOSED after 2 failures, got %s", cb.State())
	}

	// 3. 3rd infrastructure failure trips breaker to OPEN
	done, err := cb.Allow()
	if err != nil {
		t.Fatalf("unexpected allow error: %v", err)
	}
	done(store.ErrStoreUnavailable)

	if cb.State() != CircuitOpen {
		t.Fatalf("expected state OPEN after 3 failures, got %s", cb.State())
	}

	// 4. In OPEN state, Allow() fails fast with ErrCircuitOpen
	_, err = cb.Allow()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}

	// 5. Advance clock past CoolDown (5s) -> transitions to HALF_OPEN
	clock.Advance(5 * time.Second)

	if cb.State() != CircuitHalfOpen {
		t.Fatalf("expected state HALF_OPEN after cooldown, got %s", cb.State())
	}

	// 6. In HALF_OPEN, first probe is allowed
	probeDone, err := cb.Allow()
	if err != nil {
		t.Fatalf("expected probe to be allowed in HALF_OPEN, got %v", err)
	}

	// Second concurrent probe while first is in-flight is rejected
	_, err = cb.Allow()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected second concurrent probe to be rejected, got %v", err)
	}

	// Probe succeeds!
	probeDone(nil)

	// State should now recover to CLOSED!
	if cb.State() != CircuitClosed {
		t.Fatalf("expected state recovered to CLOSED, got %s", cb.State())
	}

	expectedChanges := []string{"CLOSED->OPEN", "OPEN->HALF_OPEN", "HALF_OPEN->CLOSED"}
	if len(stateChanges) != len(expectedChanges) {
		t.Fatalf("expected %d state changes, got %d: %v", len(expectedChanges), len(stateChanges), stateChanges)
	}
}

func TestCircuitBreaker_ProbeFails_ReTripsOpen(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 2,
		CoolDown:         5 * time.Second,
	}

	cb := NewCircuitBreaker(cfg, clock, nil)

	// Trip to OPEN
	for i := 0; i < 2; i++ {
		done, _ := cb.Allow()
		done(store.ErrStoreUnavailable)
	}
	if cb.State() != CircuitOpen {
		t.Fatalf("expected OPEN, got %s", cb.State())
	}

	// Advance past cooldown
	clock.Advance(5 * time.Second)

	// Probe runs but fails
	probeDone, err := cb.Allow()
	if err != nil {
		t.Fatalf("expected probe allowed, got %v", err)
	}
	probeDone(store.ErrStoreUnavailable)

	// Must re-trip back to OPEN immediately
	if cb.State() != CircuitOpen {
		t.Fatalf("expected re-trip to OPEN, got %s", cb.State())
	}
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	clock := RealClock{}
	cfg := CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 10,
		CoolDown:         100 * time.Millisecond,
	}

	cb := NewCircuitBreaker(cfg, clock, nil)

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	var blockedCount int64
	var allowedCount int64

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				done, err := cb.Allow()
				if err != nil {
					atomic.AddInt64(&blockedCount, 1)
					time.Sleep(time.Millisecond)
					continue
				}
				atomic.AddInt64(&allowedCount, 1)
				if id%5 == 0 && j%10 == 0 {
					done(store.ErrStoreUnavailable)
				} else {
					done(nil)
				}
			}
		}(i)
	}

	wg.Wait()

	if allowedCount == 0 {
		t.Fatal("expected at least some allowed operations")
	}
}

func TestCircuitBreaker_Execute(t *testing.T) {
	clock := RealClock{}
	cfg := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker(cfg, clock, nil)

	ctx := context.Background()
	called := false
	err := cb.Execute(ctx, func() error {
		called = true
		return nil
	})
	if err != nil || !called {
		t.Fatalf("Execute failed: %v, called=%v", err, called)
	}
}
