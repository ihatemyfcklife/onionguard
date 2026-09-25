package onionguard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"onionguard/store"
)

const (
	// SessionIDRawBytes specifies 32 bytes of raw cryptographic entropy (256 bits, Invariant 3).
	SessionIDRawBytes = 32

	// SessionIDStringLen specifies length of base64.RawURLEncoding string for 32 bytes (43 characters).
	SessionIDStringLen = 43

	// SessionKeyPrefix defines the store key namespace for session objects.
	SessionKeyPrefix = "session:"
)

// GenerateSessionID produces a 256-bit cryptographically unpredictable random token
// encoded as an unpadded raw URL-safe Base64 string (Invariant 3).
func GenerateSessionID() (string, error) {
	b := make([]byte, SessionIDRawBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("onionguard: crypto/rand entropy failure: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateSessionID verifies that a session token matches expected length and URL-safe base64 encoding.
func ValidateSessionID(id string) error {
	if len(id) != SessionIDStringLen {
		return fmt.Errorf("%w: invalid length %d (expected %d)", ErrInvalidSession, len(id), SessionIDStringLen)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(decoded) != SessionIDRawBytes {
		return fmt.Errorf("%w: malformed base64 encoding", ErrInvalidSession)
	}
	return nil
}

// MaskSessionID returns a safe 16-hex-character masked identifier derived from SHA-256 (Invariant 24).
// Plaintext session IDs are never rendered in logs or formatted strings.
func MaskSessionID(id string) string {
	if id == "" {
		return "[NONE]"
	}
	h := sha256.Sum256([]byte(id))
	return fmt.Sprintf("sid:%x", h[:8])
}

// Session represents the server-side lifecycle record of an anonymous client.
type Session struct {
	SessionID         string       `json:"session_id"`
	Kind              IdentityKind `json:"kind"`
	State             State        `json:"state"`
	FirstSeen         time.Time    `json:"first_seen"`
	ExpiresAt         time.Time    `json:"expires_at"`
	AbsoluteExpiresAt time.Time    `json:"absolute_expires_at,omitempty"`
	RenewalCount      int          `json:"renewal_count"`
	MaxRenewals       int          `json:"max_renewals"`
	CreatedAt         time.Time    `json:"created_at"`
	LastSeenAt        time.Time    `json:"last_seen_at"`
	ChallengeID       string       `json:"challenge_id,omitempty"`
}

// String redacts the session ID, rendering only the masked hash (Invariants 1, 24).
func (s Session) String() string {
	return fmt.Sprintf("Session{ID:%s, Kind:%s, State:%s, Renewals:%d/%d, FirstSeen:%s, ExpiresAt:%s}",
		MaskSessionID(s.SessionID), s.Kind, s.State, s.RenewalCount, s.MaxRenewals,
		s.FirstSeen.Format(time.RFC3339), s.ExpiresAt.Format(time.RFC3339))
}

// GoString redacts sensitive fields for %#v formatters.
func (s Session) GoString() string {
	return s.String()
}

// IsExpired checks whether the session has exceeded its expiration deadline (Invariant 4).
func (s *Session) IsExpired(now time.Time) bool {
	if s == nil {
		return true
	}
	if s.State == StateExpired {
		return true
	}
	if !s.ExpiresAt.IsZero() && !now.Before(s.ExpiresAt) {
		return true
	}
	return false
}

// IsRevoked checks whether the session is revoked (Invariant 5).
func (s *Session) IsRevoked() bool {
	if s == nil {
		return false
	}
	return s.State == StateRevoked
}

// SessionKey constructs the store key for a given session ID.
func SessionKey(sessionID string) string {
	return SessionKeyPrefix + sessionID
}

// NewSession instantiates a new Session struct in StateNew.
func NewSession(now time.Time, maxRenewals int) (*Session, error) {
	id, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}
	return &Session{
		SessionID:    id,
		Kind:         IdentityAnonymous,
		State:        StateNew,
		FirstSeen:    now,
		CreatedAt:    now,
		LastSeenAt:   now,
		RenewalCount: 0,
		MaxRenewals:  maxRenewals,
	}, nil
}

// SaveSession serializes and stores the session record with the specified TTL.
func SaveSession(ctx context.Context, s store.Store, sess *Session, ttl time.Duration) error {
	if s == nil {
		return store.ErrStoreClosed
	}
	if sess == nil || sess.SessionID == "" {
		return ErrInvalidSession
	}
	if ttl <= 0 {
		return store.ErrInvalidTTL
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("onionguard: failed to serialize session: %w", err)
	}
	return s.Set(ctx, SessionKey(sess.SessionID), data, ttl)
}

// GetSession retrieves and deserializes a session record from the store.
func GetSession(ctx context.Context, s store.Store, sessionID string) (*Session, error) {
	if s == nil {
		return nil, store.ErrStoreClosed
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, err
	}
	data, err := s.Get(ctx, SessionKey(sessionID))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrInvalidSession
		}
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("onionguard: failed to deserialize session: %w", err)
	}
	return &sess, nil
}

// DeleteSession removes the session from the store.
func DeleteSession(ctx context.Context, s store.Store, sessionID string) error {
	if s == nil {
		return store.ErrStoreClosed
	}
	if sessionID == "" {
		return nil
	}
	return s.Delete(ctx, SessionKey(sessionID))
}

// RevokeSession marks a session as StateRevoked under the same per-session lock
// used by rotation and admission transitions.
func RevokeSession(ctx context.Context, s store.Store, sessionID string, retentionTTL time.Duration) error {
	return RevokeSessionWithClock(ctx, s, sessionID, retentionTTL, RealClock{})
}

// RevokeSessionWithClock marks a session as StateRevoked with deterministic clock time.
func RevokeSessionWithClock(ctx context.Context, s store.Store, sessionID string, retentionTTL time.Duration, clock Clock) error {
	if s == nil {
		return store.ErrStoreClosed
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return err
	}
	if retentionTTL <= 0 {
		retentionTTL = 5 * time.Minute
	}
	if clock == nil {
		clock = RealClock{}
	}
	return withSessionLock(ctx, s, sessionID, func() error {
		sess, err := GetSession(ctx, s, sessionID)
		if err != nil {
			return err
		}
		if sess.IsRevoked() {
			return ErrSessionRevoked
		}
		sess.State = StateRevoked
		sess.ExpiresAt = time.Time{}
		sess.LastSeenAt = clock.Now()
		if err := SaveSession(ctx, s, sess, retentionTTL); err != nil {
			return err
		}
		// Release the reservation slot so capacity is freed immediately.
		if reservations, ok := s.(store.SessionReservationStore); ok {
			_ = reservations.ReleaseSession(ctx, sessionCapacityKey, sessionID)
		}
		return nil
	})
}

// RotateSession performs a serialized rotation. It validates the old session before
// consuming it and restores it when persistence of the replacement fails.
func RotateSession(ctx context.Context, s store.Store, oldSessionID string, sessionTTL time.Duration, clock Clock) (*Session, error) {
	if s == nil {
		return nil, store.ErrStoreClosed
	}
	if err := ValidateSessionID(oldSessionID); err != nil {
		return nil, err
	}
	if sessionTTL <= 0 {
		return nil, store.ErrInvalidTTL
	}
	if clock == nil {
		clock = RealClock{}
	}

	var out *Session
	err := withSessionLock(ctx, s, oldSessionID, func() error {
		oldSess, err := GetSession(ctx, s, oldSessionID)
		if err != nil {
			return err
		}
		now := clock.Now()
		if oldSess.IsRevoked() {
			return ErrSessionRevoked
		}
		if oldSess.IsExpired(now) {
			return ErrSessionExpired
		}
		if oldSess.State != StateAdmitted && oldSess.State != StateRotating {
			return ErrInvalidTransition
		}
		if oldSess.MaxRenewals > 0 && oldSess.RenewalCount >= oldSess.MaxRenewals {
			return ErrRenewalLimitReached
		}

		newID, err := GenerateSessionID()
		if err != nil {
			return err
		}
		expiry := now.Add(sessionTTL)
		if !oldSess.AbsoluteExpiresAt.IsZero() && oldSess.AbsoluteExpiresAt.Before(expiry) {
			expiry = oldSess.AbsoluteExpiresAt
		}
		if !expiry.After(now) {
			return ErrSessionExpired
		}
		next := &Session{
			SessionID: newID, Kind: oldSess.Kind, State: StateAdmitted,
			FirstSeen: oldSess.FirstSeen, ExpiresAt: expiry,
			AbsoluteExpiresAt: oldSess.AbsoluteExpiresAt, RenewalCount: oldSess.RenewalCount + 1,
			MaxRenewals: oldSess.MaxRenewals, CreatedAt: oldSess.CreatedAt, LastSeenAt: now,
		}
		ttl := expiry.Sub(now)
		if err := SaveSession(ctx, s, next, ttl); err != nil {
			return err
		}
		if err := s.Delete(ctx, SessionKey(oldSessionID)); err != nil {
			_ = s.Delete(context.Background(), SessionKey(newID))
			return err
		}
		// Transfer the reservation from old session ID to new session ID atomically.
		// Best-effort: on failure the old reservation expires via TTL naturally.
		if reservations, ok := s.(store.SessionReservationStore); ok {
			_ = reservations.MoveSessionReservation(ctx, sessionCapacityKey, oldSessionID, newID, expiry)
		}
		out = next
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func remainingTTL(sess *Session, now time.Time, fallback time.Duration) time.Duration {
	if sess != nil && !sess.ExpiresAt.IsZero() {
		if d := sess.ExpiresAt.Sub(now); d > 0 {
			return d
		}
	}
	if sess != nil && !sess.AbsoluteExpiresAt.IsZero() {
		if d := sess.AbsoluteExpiresAt.Sub(now); d > 0 {
			return d
		}
	}
	if fallback > 0 {
		return fallback
	}
	return time.Second
}
