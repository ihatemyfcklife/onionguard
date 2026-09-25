package onionguard

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"onionguard/store"
)

type testReliabilityObserver struct {
	stateChanges   []string
	storeErrors    []string
	lockContentions int
	mu             sync.Mutex
}

func (o *testReliabilityObserver) OnRequestAdmitted(IdentityKind) {}
func (o *testReliabilityObserver) OnWaitRoomQueued(time.Duration) {}
func (o *testReliabilityObserver) OnChallengeIssued()             {}
func (o *testReliabilityObserver) OnChallengeSolved()             {}
func (o *testReliabilityObserver) OnChallengeFailed()             {}
func (o *testReliabilityObserver) OnRateLimited(IdentityKind)     {}

func (o *testReliabilityObserver) OnCircuitBreakerStateChanged(from, to string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stateChanges = append(o.stateChanges, from+"->"+to)
}

func (o *testReliabilityObserver) OnStoreError(op string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.storeErrors = append(o.storeErrors, op+": "+err.Error())
}

func (o *testReliabilityObserver) OnLockContention(d time.Duration, attempts int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lockContentions++
}

// TestReliability_CircuitBreaker_TripsAndFastFails verifies that when the storage backend
// fails repeatedly, the Circuit Breaker trips to OPEN, fast-failing subsequent requests with 503
// in microseconds, avoiding thread/goroutine accumulation and preventing a thundering herd.
func TestReliability_CircuitBreaker_TripsAndFastFails(t *testing.T) {
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	obs := &testReliabilityObserver{}

	// Configure engine pointing to an unreachable Redis port to simulate an outage
	cfg := DefaultConfig()
	cfg.Clock = clock
	cfg.StoreConfig.Type = StoreTypeRedis
	cfg.StoreConfig.RedisAddr = "127.0.0.1:6399"
	cfg.StoreConfig.RedisDialTimeout = 20 * time.Millisecond
	cfg.StoreConfig.RedisFailClosed = true
	cfg.CircuitBreaker.Enabled = true
	cfg.CircuitBreaker.FailureThreshold = 3
	cfg.CircuitBreaker.CoolDown = 5 * time.Second

	engine, err := New(cfg, WithMetricsObserver(obs))
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}
	defer engine.Close()

	ctx := context.Background()

	// 1. Initial state is CLOSED
	if engine.CircuitBreaker().State() != CircuitClosed {
		t.Fatalf("expected initial state CLOSED, got %s", engine.CircuitBreaker().State())
	}

	// 2. Perform requests failing against unreachable Redis until threshold (3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "http://example.test/", nil)
		_, err := engine.AuthorizeRequest(ctx, req)
		if err == nil {
			t.Fatalf("expected error on unreachable Redis, got nil")
		}
	}

	// 3. Breaker MUST now be OPEN!
	if engine.CircuitBreaker().State() != CircuitOpen {
		t.Fatalf("expected state OPEN after 3 failures, got %s", engine.CircuitBreaker().State())
	}

	// 4. Fast-Fail check: 100 concurrent requests must fail instantly with ErrCircuitOpen (< 100ms total)
	start := time.Now()
	const concurrent = 100
	var wg sync.WaitGroup
	var fastFailCount int64

	wg.Add(concurrent)
	for i := 0; i < concurrent; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "http://example.test/", nil)
			_, err := engine.AuthorizeRequest(ctx, req)
			if errors.Is(err, ErrCircuitOpen) {
				atomic.AddInt64(&fastFailCount, 1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	if fastFailCount != concurrent {
		t.Errorf("expected %d fast-fail requests, got %d", concurrent, fastFailCount)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("fast-fail took too long: %v (expected < 500ms for 100 fast fails)", elapsed)
	}

	// Verify Ping also returns ErrCircuitOpen when breaker is open
	if err := engine.Ping(ctx); !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected engine.Ping to return ErrCircuitOpen, got %v", err)
	}

	// 5. Verify metrics observer recorded state change and store errors
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.stateChanges) == 0 || obs.stateChanges[0] != "CLOSED->OPEN" {
		t.Errorf("expected CLOSED->OPEN state change, got: %v", obs.stateChanges)
	}
	if len(obs.storeErrors) == 0 {
		t.Errorf("expected recorded store errors in observer, got 0")
	}
}

// TestReliability_GracefulShutdown_DrainsInFlight verifies that Shutdown() waits for
// in-flight requests to complete before closing the storage backend, while rejecting new requests.
func TestReliability_GracefulShutdown_DrainsInFlight(t *testing.T) {
	memStore, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.Store = memStore

	engine, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	inFlightStarted := make(chan struct{})
	inFlightDone := make(chan struct{})

	// Simulate an active in-flight request that takes 150ms
	var inFlightSucceeded bool
	go func() {
		engine.inFlight.Add(1)
		defer engine.inFlight.Done()
		close(inFlightStarted)

		time.Sleep(150 * time.Millisecond)
		inFlightSucceeded = true
		close(inFlightDone)
	}()

	<-inFlightStarted

	// Trigger Shutdown concurrently with a 2-second timeout
	shutdownStarted := time.Now()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	// While shutdown is in progress, new requests MUST be rejected immediately with ErrStoreClosed
	newReq := httptest.NewRequest("GET", "http://example.test/", nil)
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, err := engine.AuthorizeRequest(ctx, newReq)
		if !errors.Is(err, ErrStoreClosed) {
			t.Errorf("expected new request during shutdown to be rejected with ErrStoreClosed, got: %v", err)
		}
	}()

	err = engine.Shutdown(shutdownCtx)
	if err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	shutdownElapsed := time.Since(shutdownStarted)
	if shutdownElapsed < 140*time.Millisecond {
		t.Errorf("Shutdown returned too quickly without waiting for in-flight: %v", shutdownElapsed)
	}

	<-inFlightDone
	if !inFlightSucceeded {
		t.Error("in-flight request was aborted prematurely")
	}
}

// TestReliability_RedisConfig_SentinelAndClusterOptions verifies that RedisConfig correctly
// configures Sentinel and Cluster topology parameters without panicking.
func TestReliability_RedisConfig_SentinelAndClusterOptions(t *testing.T) {
	// 1. Sentinel config
	cfgSentinel := DefaultConfig()
	cfgSentinel.StoreConfig.Type = StoreTypeRedis
	cfgSentinel.StoreConfig.RedisSentinelAddrs = []string{"127.0.0.1:26379", "127.0.0.1:26380"}
	cfgSentinel.StoreConfig.RedisSentinelMaster = "mymaster"
	cfgSentinel.StoreConfig.RedisSentinelPassword = "secret-sentinel-password"
	cfgSentinel.StoreConfig.RedisPassword = "redis-cluster-password"

	if err := cfgSentinel.Validate(); err != nil {
		t.Fatalf("valid sentinel config failed validation: %v", err)
	}

	// Ensure passwords are redacted in String() / GoString()
	strOutput := cfgSentinel.StoreConfig.String()
	if !containsString(strOutput, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in StoreConfig.String(), got: %s", strOutput)
	}
	if containsString(strOutput, "secret-sentinel-password") || containsString(strOutput, "redis-cluster-password") {
		t.Errorf("passwords leaked in StoreConfig.String(): %s", strOutput)
	}

	// 2. Cluster config
	cfgCluster := DefaultConfig()
	cfgCluster.StoreConfig.Type = StoreTypeRedis
	cfgCluster.StoreConfig.RedisClusterAddrs = []string{"127.0.0.1:7000", "127.0.0.1:7001"}
	if err := cfgCluster.Validate(); err != nil {
		t.Fatalf("valid cluster config failed validation: %v", err)
	}
}

func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || len(needle) > 0 && func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	}())
}
