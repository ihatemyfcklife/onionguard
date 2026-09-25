package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound         = errors.New("onionguard: store key not found")
	ErrCapacityExceeded = errors.New("onionguard: store capacity exceeded")
	ErrKeyTooLarge      = errors.New("onionguard: key size exceeds limit")
	ErrValueTooLarge    = errors.New("onionguard: value size exceeds limit")
	ErrStoreClosed      = errors.New("onionguard: store is closed")
	ErrStoreUnavailable = errors.New("onionguard: store is unavailable")
	ErrInvalidTTL       = errors.New("onionguard: invalid ttl")
	ErrInvalidValue     = errors.New("onionguard: invalid value")
	ErrLockUnavailable  = errors.New("onionguard: distributed lock unavailable")
)

type Store interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, val []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	GetDel(ctx context.Context, key string) ([]byte, error)
	SetNX(ctx context.Context, key string, val []byte, ttl time.Duration) (bool, error)
	IncrementWithTTL(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
	Close() error
}

// ConditionalDeleter is an optional backend capability used for safe lock release.
type ConditionalDeleter interface {
	CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error)
}

// ConditionalToucher renews a lock only when its ownership token still matches.
type ConditionalToucher interface {
	CompareAndTouch(ctx context.Context, key string, expected []byte, ttl time.Duration) (bool, error)
}

// TokenBucketStore is an optional backend capability for distributed token buckets.
type TokenBucketStore interface {
	ConsumeToken(ctx context.Context, key string, rate float64, burst int, cost int64, ttl time.Duration, now time.Time) (allowed bool, retryAfter time.Duration, err error)
}

// SessionReservationStore atomically tracks expiring active-session reservations.
type SessionReservationStore interface {
	ReserveSession(ctx context.Context, namespace, sessionID string, limit int, expiresAt time.Time) (bool, error)
	ReleaseSession(ctx context.Context, namespace, sessionID string) error
	MoveSessionReservation(ctx context.Context, namespace, oldSessionID, newSessionID string, expiresAt time.Time) error
}

// TouchableStore is an optional capability to renew a TTL without changing the value.
type TouchableStore interface {
	Touch(ctx context.Context, key string, ttl time.Duration) error
}

// Clock provides time retrieval for stores supporting deterministic testing and virtual time.
type Clock interface {
	Now() time.Time
}

// ClockSetter is an optional capability for stores that can synchronize with an external Clock.
type ClockSetter interface {
	SetClock(c Clock)
}

// Pinger is an optional capability for stores that can verify connectivity/liveness.
type Pinger interface {
	Ping(ctx context.Context) error
}
