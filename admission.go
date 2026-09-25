package onionguard

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"onionguard/store"
)

type State string

const (
	StateNew               State = "NEW"
	StateWaiting           State = "WAITING"
	StateChallengeRequired State = "CHALLENGE_REQUIRED"
	StateAdmitted          State = "ADMITTED"
	StateExpired           State = "EXPIRED"
	StateRevoked           State = "REVOKED"
	StateRotating          State = "ROTATING"
)

type AdmissionState = State

type Event string

const (
	EventNewClient         Event = "NEW_CLIENT"
	EventWaitElapsed       Event = "WAIT_ELAPSED"
	EventChallengeRequired Event = "CHALLENGE_REQUIRED"
	EventChallengeSolved   Event = "CHALLENGE_SOLVED"
	EventChallengeFailed   Event = "CHALLENGE_FAILED"
	EventExpire            Event = "EXPIRE"
	EventRevoke            Event = "REVOKE"
	EventRotate            Event = "ROTATE"
)

func IsLegalTransition(from State, event Event, to State) bool {
	switch from {
	case StateNew:
		switch event {
		case EventNewClient:
			return to == StateWaiting || to == StateChallengeRequired || to == StateAdmitted
		case EventExpire:
			return to == StateExpired
		case EventRevoke:
			return to == StateRevoked
		}
	case StateWaiting:
		switch event {
		case EventWaitElapsed:
			return to == StateChallengeRequired || to == StateAdmitted
		case EventChallengeRequired:
			return to == StateChallengeRequired
		case EventExpire:
			return to == StateExpired
		case EventRevoke:
			return to == StateRevoked
		}
	case StateChallengeRequired:
		switch event {
		case EventChallengeSolved:
			return to == StateAdmitted
		case EventChallengeRequired:
			return to == StateChallengeRequired
		case EventChallengeFailed:
			return to == StateWaiting || to == StateRevoked
		case EventExpire:
			return to == StateExpired
		case EventRevoke:
			return to == StateRevoked
		}
	case StateAdmitted:
		switch event {
		case EventRotate:
			return to == StateRotating || to == StateAdmitted
		case EventExpire:
			return to == StateExpired
		case EventRevoke:
			return to == StateRevoked
		}
	case StateRotating:
		switch event {
		case EventRotate:
			return to == StateAdmitted
		case EventExpire:
			return to == StateExpired
		case EventRevoke:
			return to == StateRevoked
		}
	case StateExpired:
		return event == EventRevoke && to == StateRevoked
	case StateRevoked:
		return false
	}
	return false
}

type AdmissionDecision struct {
	Allowed     bool          `json:"allowed"`
	State       State         `json:"state"`
	RetryAfter  time.Duration `json:"retry_after,omitempty"`
	ChallengeID string        `json:"challenge_id,omitempty"`
	Session     *Session      `json:"-"`
	Error       error         `json:"-"`
}

type AdmissionEngine struct {
	config Config
	store  store.Store
	clock  Clock
}

const sessionCapacityKey = "admission:session-capacity"

func NewAdmissionEngine(cfg Config, s store.Store, clock Clock) *AdmissionEngine {
	if clock == nil {
		clock = RealClock{}
	}
	if setter, ok := s.(store.ClockSetter); ok {
		setter.SetClock(clock)
	}
	return &AdmissionEngine{config: cfg, store: s, clock: clock}
}

func (ae *AdmissionEngine) now() time.Time {
	if ae != nil && ae.clock != nil {
		return ae.clock.Now()
	}
	return time.Now()
}

func (ae *AdmissionEngine) Evaluate(ctx context.Context, sess *Session) (AdmissionDecision, error) {
	return ae.evaluate(ctx, sess, false)
}

// EvaluateFresh evaluates an already verified and freshly retrieved session snapshot without
// performing a redundant store lookup.
func (ae *AdmissionEngine) EvaluateFresh(ctx context.Context, sess *Session) (AdmissionDecision, error) {
	return ae.evaluate(ctx, sess, true)
}

func (ae *AdmissionEngine) evaluate(ctx context.Context, sess *Session, freshSnapshot bool) (AdmissionDecision, error) {
	if ae == nil {
		return AdmissionDecision{Allowed: false, State: StateNew, Error: ErrEngineNotInitialized}, ErrEngineNotInitialized
	}
	if sess == nil {
		return AdmissionDecision{Allowed: false, State: StateNew, Error: ErrInvalidSession}, nil
	}
	cur := *sess
	now := ae.now()
	// Handle terminal conditions on the supplied snapshot first so callers can evaluate
	// freshly constructed expired/revoked objects before they are persisted.
	if cur.IsRevoked() {
		return AdmissionDecision{Allowed: false, State: StateRevoked, Session: &cur, Error: ErrSessionRevoked}, nil
	}
	if cur.IsExpired(now) {
		cur.State = StateExpired
		return AdmissionDecision{Allowed: false, State: StateExpired, Session: &cur, Error: ErrSessionExpired}, nil
	}

	// Once a session exists in storage, the store is authoritative. This prevents stale
	// request objects from resurrecting rotated/deleted sessions and keeps Evaluate read-only
	// with respect to the caller's *Session pointer.
	// When freshSnapshot is true, the session was already retrieved from the store during
	// the current request, safely avoiding a redundant store read.
	if !freshSnapshot && ae.store != nil && cur.SessionID != "" {
		fresh, err := GetSession(ctx, ae.store, cur.SessionID)
		if err == nil {
			cur = *fresh
		} else if !errors.Is(err, ErrInvalidSession) {
			return AdmissionDecision{Allowed: false, State: cur.State, Session: &cur, Error: err}, err
		} else if cur.State == StateAdmitted || cur.State == StateChallengeRequired || cur.State == StateWaiting {
			return AdmissionDecision{Allowed: false, State: StateExpired, Session: &cur, Error: ErrInvalidSession}, ErrInvalidSession
		}
	}

	if cur.IsRevoked() {
		return AdmissionDecision{Allowed: false, State: StateRevoked, Session: &cur, Error: ErrSessionRevoked}, nil
	}
	if cur.IsExpired(now) {
		cur.State = StateExpired
		return AdmissionDecision{Allowed: false, State: StateExpired, Session: &cur, Error: ErrSessionExpired}, nil
	}

	switch cur.State {
	case StateAdmitted:
		// Do not persist LastSeenAt on every request. Admission evaluation is deliberately
		// read-only to avoid resurrecting stale session IDs and to keep concurrent evaluation race-free.
		return AdmissionDecision{Allowed: true, State: StateAdmitted, Session: &cur}, nil
	case StateWaiting:
		elapsed := now.Sub(cur.FirstSeen)
		if elapsed < 0 {
			elapsed = 0
		}
		if elapsed < ae.config.WaitRoom.WaitTime {
			rem := ae.config.WaitRoom.WaitTime - elapsed
			retry := time.Duration(math.Ceil(rem.Seconds())) * time.Second
			if retry < time.Second {
				retry = time.Second
			}
			return AdmissionDecision{Allowed: false, State: StateWaiting, RetryAfter: retry, Session: &cur, Error: ErrWaitTimeNotElapsed}, nil
		}
		return ae.handleWaitElapsed(ctx, &cur)
	case StateChallengeRequired:
		return AdmissionDecision{Allowed: false, State: StateChallengeRequired, ChallengeID: cur.ChallengeID, Session: &cur}, nil
	case StateNew:
		return ae.handleNewClient(ctx, &cur)
	default:
		return AdmissionDecision{Allowed: false, State: cur.State, Session: &cur, Error: ErrInvalidTransition}, nil
	}
}

func (ae *AdmissionEngine) reserveSession(ctx context.Context, sessionID string, ttl time.Duration) (func(), error) {
	if ae.store == nil || ae.config.MaxConcurrentSessions <= 0 {
		return func() {}, nil
	}
	reservations, ok := ae.store.(store.SessionReservationStore)
	if !ok {
		return nil, ErrInvalidValue
	}
	ok, err := reservations.ReserveSession(ctx, sessionCapacityKey, sessionID, ae.config.MaxConcurrentSessions, ae.clock.Now().Add(ttl))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrCapacityExceeded
	}
	return func() { _ = reservations.ReleaseSession(context.Background(), sessionCapacityKey, sessionID) }, nil
}

// releaseReservation frees a session reservation slot. It is best-effort: errors
// are silently ignored because the reservation will expire naturally via TTL.
func (ae *AdmissionEngine) releaseReservation(ctx context.Context, sessionID string) {
	if ae.store == nil || ae.config.MaxConcurrentSessions <= 0 {
		return
	}
	if reservations, ok := ae.store.(store.SessionReservationStore); ok {
		_ = reservations.ReleaseSession(ctx, sessionCapacityKey, sessionID)
	}
}

// renewReservation updates the expiration of an existing reservation without
// changing the session count. It calls ReserveSession which is idempotent for
// existing members (both MemoryStore and RedisStore update the expiry score).
func (ae *AdmissionEngine) renewReservation(ctx context.Context, sessionID string, ttl time.Duration) {
	if ae.store == nil || ae.config.MaxConcurrentSessions <= 0 {
		return
	}
	if reservations, ok := ae.store.(store.SessionReservationStore); ok {
		_, _ = reservations.ReserveSession(ctx, sessionCapacityKey, sessionID, ae.config.MaxConcurrentSessions, ae.clock.Now().Add(ttl))
	}
}

func (ae *AdmissionEngine) handleNewClient(ctx context.Context, sess *Session) (AdmissionDecision, error) {
	now := ae.clock.Now()
	sess.LastSeenAt = now
	if sess.FirstSeen.IsZero() {
		sess.FirstSeen = now
	}
	if ae.config.SessionAbsoluteLifetime > 0 {
		sess.AbsoluteExpiresAt = now.Add(ae.config.SessionAbsoluteLifetime)
	}
	if ae.config.WaitRoom.Enabled {
		sess.State = StateWaiting
		ttl := ae.config.WaitRoom.WaitTime + 10*time.Minute
		if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(now.Add(ttl)) {
			ttl = sess.AbsoluteExpiresAt.Sub(now)
		}
		if ttl <= 0 {
			return AdmissionDecision{Allowed: false, State: StateExpired, Session: sess, Error: ErrSessionExpired}, ErrSessionExpired
		}
		sess.ExpiresAt = now.Add(ttl)
		if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(sess.ExpiresAt) {
			sess.ExpiresAt = sess.AbsoluteExpiresAt
		}
		reservationTTL := sess.ExpiresAt.Sub(now)
		release, err := ae.reserveSession(ctx, sess.SessionID, reservationTTL)
		if err != nil {
			return AdmissionDecision{Allowed: false, State: StateNew, Session: sess, Error: err}, err
		}
		if ae.store != nil {
			if err := SaveSession(ctx, ae.store, sess, reservationTTL); err != nil {
				release()
				return AdmissionDecision{}, err
			}
		}
		return AdmissionDecision{Allowed: false, State: StateWaiting, RetryAfter: ae.config.WaitRoom.WaitTime, Session: sess, Error: ErrWaitTimeNotElapsed}, nil
	}
	if ae.config.Captcha.Enabled {
		sess.State = StateChallengeRequired
		ttl := ae.config.Captcha.TTL + 5*time.Minute
		if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(now.Add(ttl)) {
			ttl = sess.AbsoluteExpiresAt.Sub(now)
		}
		if ttl <= 0 {
			return AdmissionDecision{Allowed: false, State: StateExpired, Session: sess, Error: ErrSessionExpired}, ErrSessionExpired
		}
		sess.ExpiresAt = now.Add(ttl)
		if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(sess.ExpiresAt) {
			sess.ExpiresAt = sess.AbsoluteExpiresAt
		}
		reservationTTL := sess.ExpiresAt.Sub(now)
		release, err := ae.reserveSession(ctx, sess.SessionID, reservationTTL)
		if err != nil {
			return AdmissionDecision{Allowed: false, State: StateNew, Session: sess, Error: err}, err
		}
		if ae.store != nil {
			if err := SaveSession(ctx, ae.store, sess, reservationTTL); err != nil {
				release()
				return AdmissionDecision{}, err
			}
		}
		return AdmissionDecision{Allowed: false, State: StateChallengeRequired, Session: sess}, nil
	}
	sess.State = StateAdmitted
	sess.ExpiresAt = now.Add(ae.config.SessionTTL)
	if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(sess.ExpiresAt) {
		sess.ExpiresAt = sess.AbsoluteExpiresAt
	}
	ttl := sess.ExpiresAt.Sub(now)
	if ttl <= 0 {
		return AdmissionDecision{Allowed: false, State: StateExpired, Session: sess, Error: ErrSessionExpired}, ErrSessionExpired
	}
	release, err := ae.reserveSession(ctx, sess.SessionID, ttl)
	if err != nil {
		return AdmissionDecision{Allowed: false, State: StateNew, Session: sess, Error: err}, err
	}
	if ae.store != nil {
		if err := SaveSession(ctx, ae.store, sess, ttl); err != nil {
			release()
			return AdmissionDecision{}, err
		}
	}
	return AdmissionDecision{Allowed: true, State: StateAdmitted, Session: sess}, nil
}

func (ae *AdmissionEngine) handleWaitElapsed(ctx context.Context, input *Session) (AdmissionDecision, error) {
	if ae.store == nil {
		return AdmissionDecision{}, store.ErrStoreClosed
	}
	var out AdmissionDecision
	err := withSessionLock(ctx, ae.store, input.SessionID, func() error {
		fresh, err := GetSession(ctx, ae.store, input.SessionID)
		if err != nil {
			return err
		}
		now := ae.clock.Now()
		if fresh.IsRevoked() {
			out = AdmissionDecision{Allowed: false, State: StateRevoked, Session: fresh, Error: ErrSessionRevoked}
			return nil
		}
		if fresh.IsExpired(now) {
			fresh.State = StateExpired
			out = AdmissionDecision{Allowed: false, State: StateExpired, Session: fresh, Error: ErrSessionExpired}
			return nil
		}
		if fresh.State != StateWaiting {
			returnErr := error(nil)
			switch fresh.State {
			case StateAdmitted:
				out = AdmissionDecision{Allowed: true, State: StateAdmitted, Session: fresh}
			case StateChallengeRequired:
				out = AdmissionDecision{Allowed: false, State: StateChallengeRequired, ChallengeID: fresh.ChallengeID, Session: fresh}
			default:
				returnErr = ErrInvalidTransition
			}
			return returnErr
		}
		if now.Sub(fresh.FirstSeen) < ae.config.WaitRoom.WaitTime {
			rem := ae.config.WaitRoom.WaitTime - now.Sub(fresh.FirstSeen)
			retry := time.Duration(math.Ceil(rem.Seconds())) * time.Second
			if retry < time.Second {
				retry = time.Second
			}
			out = AdmissionDecision{Allowed: false, State: StateWaiting, RetryAfter: retry, Session: fresh, Error: ErrWaitTimeNotElapsed}
			return nil
		}
		if ae.config.Captcha.Enabled {
			fresh.State = StateChallengeRequired
			fresh.LastSeenAt = now
			ttl := ae.config.Captcha.TTL + 5*time.Minute
			if !fresh.AbsoluteExpiresAt.IsZero() && fresh.AbsoluteExpiresAt.Before(now.Add(ttl)) {
				ttl = fresh.AbsoluteExpiresAt.Sub(now)
			}
			if ttl <= 0 {
				fresh.State = StateExpired
				out = AdmissionDecision{Allowed: false, State: StateExpired, Session: fresh, Error: ErrSessionExpired}
				return nil
			}
			fresh.ExpiresAt = now.Add(ttl)
			if !fresh.AbsoluteExpiresAt.IsZero() && fresh.AbsoluteExpiresAt.Before(fresh.ExpiresAt) {
				fresh.ExpiresAt = fresh.AbsoluteExpiresAt
			}
			if err := SaveSession(ctx, ae.store, fresh, fresh.ExpiresAt.Sub(now)); err != nil {
				return err
			}
			ae.renewReservation(ctx, fresh.SessionID, fresh.ExpiresAt.Sub(now))
			out = AdmissionDecision{Allowed: false, State: StateChallengeRequired, Session: fresh}
			return nil
		}
		fresh.State = StateAdmitted
		fresh.LastSeenAt = now
		fresh.ExpiresAt = now.Add(ae.config.SessionTTL)
		if !fresh.AbsoluteExpiresAt.IsZero() && fresh.AbsoluteExpiresAt.Before(fresh.ExpiresAt) {
			fresh.ExpiresAt = fresh.AbsoluteExpiresAt
		}
		ttl := fresh.ExpiresAt.Sub(now)
		if ttl <= 0 {
			fresh.State = StateExpired
			out = AdmissionDecision{Allowed: false, State: StateExpired, Session: fresh, Error: ErrSessionExpired}
			return nil
		}
		if err := SaveSession(ctx, ae.store, fresh, ttl); err != nil {
			return err
		}
		ae.renewReservation(ctx, fresh.SessionID, ttl)
		out = AdmissionDecision{Allowed: true, State: StateAdmitted, Session: fresh}
		return nil
	})
	if err != nil {
		return AdmissionDecision{}, err
	}
	return out, nil
}

func (ae *AdmissionEngine) Transition(ctx context.Context, sessionID string, event Event, target State) (*Session, error) {
	if ae == nil || ae.store == nil {
		return nil, store.ErrStoreClosed
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, err
	}
	var result *Session
	err := withSessionLock(ctx, ae.store, sessionID, func() error {
		sess, err := GetSession(ctx, ae.store, sessionID)
		if err != nil {
			return err
		}
		if sess.State == target {
			result = sess
			return nil
		}
		if !IsLegalTransition(sess.State, event, target) {
			return fmt.Errorf("%w: cannot transition from %s to %s via %s", ErrInvalidTransition, sess.State, target, event)
		}
		now := ae.clock.Now()
		sess.State = target
		sess.LastSeenAt = now
		ttl := ae.config.SessionTTL
		switch target {
		case StateAdmitted:
			sess.ExpiresAt = now.Add(ae.config.SessionTTL)
			if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(sess.ExpiresAt) {
				sess.ExpiresAt = sess.AbsoluteExpiresAt
			}
			ttl = sess.ExpiresAt.Sub(now)
		case StateRevoked:
			ttl = 5 * time.Minute
			sess.ExpiresAt = time.Time{}
		case StateExpired:
			ttl = time.Minute
			sess.ExpiresAt = now
		}
		if ttl <= 0 {
			return ErrSessionExpired
		}
		if err := SaveSession(ctx, ae.store, sess, ttl); err != nil {
			return err
		}
		// Manage reservation after successful persistence.
		switch target {
		case StateRevoked, StateExpired:
			ae.releaseReservation(ctx, sess.SessionID)
		case StateAdmitted:
			ae.renewReservation(ctx, sess.SessionID, ttl)
		}
		result = sess
		return nil
	})
	return result, err
}
