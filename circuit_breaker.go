package onionguard

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"onionguard/store"
)

// CircuitState represents the current operating state of the CircuitBreaker.
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "CLOSED"
	case CircuitOpen:
		return "OPEN"
	case CircuitHalfOpen:
		return "HALF_OPEN"
	default:
		return fmt.Sprintf("CircuitState(%d)", s)
	}
}

// CircuitBreakerConfig controls the automatic failure isolation and recovery thresholds.
type CircuitBreakerConfig struct {
	Enabled          bool          // If true, enables circuit breaking (default: true)
	FailureThreshold int           // Consecutive infrastructure failures to trip open (default: 5)
	CoolDown         time.Duration // Duration to remain open before probing in half-open (default: 5s)
}

// DefaultCircuitBreakerConfig returns resilient production defaults.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		Enabled:          true,
		FailureThreshold: 5,
		CoolDown:         5 * time.Second,
	}
}

// CircuitBreaker prevents thundering herds and resource exhaustion during storage outages.
// When tripped open, it fails incoming store operations immediately in <1µs (HTTP 503)
// without creating socket connections or piling up goroutines.
type CircuitBreaker struct {
	mu               sync.Mutex
	cfg              CircuitBreakerConfig
	state            CircuitState
	failures         int
	lastStateChange  time.Time
	halfOpenInFlight bool
	clock            Clock
	onStateChange    func(from, to CircuitState)
}

// NewCircuitBreaker creates a new CircuitBreaker.
func NewCircuitBreaker(cfg CircuitBreakerConfig, clock Clock, onStateChange func(from, to CircuitState)) *CircuitBreaker {
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.CoolDown <= 0 {
		cfg.CoolDown = 5 * time.Second
	}
	if clock == nil {
		clock = RealClock{}
	}
	return &CircuitBreaker{
		cfg:             cfg,
		state:           CircuitClosed,
		clock:           clock,
		lastStateChange: clock.Now(),
		onStateChange:   onStateChange,
	}
}

func (cb *CircuitBreaker) now() time.Time {
	if cb != nil && cb.clock != nil {
		return cb.clock.Now()
	}
	return time.Now()
}

// State returns the current CircuitState.
func (cb *CircuitBreaker) State() CircuitState {
	if cb == nil {
		return CircuitClosed
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.currentStateLocked(cb.now())
}

func (cb *CircuitBreaker) currentStateLocked(now time.Time) CircuitState {
	if cb.state == CircuitOpen {
		if now.Sub(cb.lastStateChange) >= cb.cfg.CoolDown {
			cb.transitionLocked(CircuitHalfOpen, now)
		}
	}
	return cb.state
}

func (cb *CircuitBreaker) transitionLocked(to CircuitState, now time.Time) {
	from := cb.state
	if from == to {
		return
	}
	cb.state = to
	cb.lastStateChange = now
	cb.halfOpenInFlight = false
	if to == CircuitClosed {
		cb.failures = 0
	}
	if cb.onStateChange != nil {
		cb.onStateChange(from, to)
	}
}

// Allow checks whether an operation is allowed to proceed.
// If allowed, it returns a done callback that MUST be called with the operation's error.
// If disallowed (circuit is open), it returns ErrCircuitOpen immediately.
func (cb *CircuitBreaker) Allow() (done func(err error), err error) {
	if cb == nil || !cb.cfg.Enabled {
		return func(error) {}, nil
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := cb.now()
	state := cb.currentStateLocked(now)

	switch state {
	case CircuitOpen:
		return nil, ErrCircuitOpen

	case CircuitHalfOpen:
		if cb.halfOpenInFlight {
			// Probe request is already in progress; fast-fail other requests
			return nil, ErrCircuitOpen
		}
		cb.halfOpenInFlight = true
		return func(opErr error) { cb.report(opErr) }, nil

	default: // CircuitClosed
		return func(opErr error) { cb.report(opErr) }, nil
	}
}

// Execute runs the given function guarded by the circuit breaker.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func() error) error {
	done, err := cb.Allow()
	if err != nil {
		return err
	}
	opErr := fn()
	done(opErr)
	return opErr
}

// report updates circuit breaker state based on the error result.
func (cb *CircuitBreaker) report(err error) {
	if cb == nil || !cb.cfg.Enabled {
		return
	}
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := cb.now()

	// Only infrastructure / storage-level errors trip the breaker.
	// Normal application errors (key not found, bad session, wrong captcha) do not.
	isInfraErr := isInfrastructureError(err)

	if !isInfraErr {
		// Successful or non-infrastructure operation
		if cb.state == CircuitHalfOpen {
			cb.transitionLocked(CircuitClosed, now)
		} else if cb.state == CircuitClosed {
			cb.failures = 0
		}
		cb.halfOpenInFlight = false
		return
	}

	// Infrastructure error occurred
	if cb.state == CircuitHalfOpen {
		cb.transitionLocked(CircuitOpen, now)
		return
	}

	if cb.state == CircuitClosed {
		cb.failures++
		if cb.failures >= cb.cfg.FailureThreshold {
			cb.transitionLocked(CircuitOpen, now)
		}
	}
}

// isInfrastructureError determines if an error indicates a storage or network failure.
func isInfrastructureError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, store.ErrStoreUnavailable) ||
		errors.Is(err, store.ErrStoreClosed) ||
		errors.Is(err, store.ErrLockUnavailable)
}
