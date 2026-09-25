package onionguard

import (
	"sync"
	"time"
)

// Clock provides an interface for time operations, enabling deterministic testing.
type Clock interface {
	Now() time.Time
	Sleep(d time.Duration)
}

// RealClock implements Clock using the standard Go time package.
type RealClock struct{}

// Now returns the current wall clock time.
func (RealClock) Now() time.Time {
	return time.Now()
}

// Sleep pauses the current goroutine for the duration d.
func (RealClock) Sleep(d time.Duration) {
	time.Sleep(d)
}

// TestClock provides a thread-safe mock clock for deterministic testing.
type TestClock struct {
	mu      sync.RWMutex
	current time.Time
}

// NewTestClock initializes a TestClock at the given start time.
// If start is zero, it defaults to a fixed epoch (2026-01-01T00:00:00Z).
func NewTestClock(start time.Time) *TestClock {
	if start.IsZero() {
		start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	return &TestClock{current: start}
}

// Now returns the simulated current time under read lock.
func (c *TestClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// Sleep advances the simulated clock by duration d immediately (instant sleep).
func (c *TestClock) Sleep(d time.Duration) {
	c.Advance(d)
}

// Advance moves the simulated time forward by duration d under write lock.
func (c *TestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = c.current.Add(d)
}

// Set sets the simulated time to a specific time t under write lock.
func (c *TestClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = t
}
