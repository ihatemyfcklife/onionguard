package onionguard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

type CaptchaChallenge struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Attempts     int       `json:"attempts"`
	MaxAttempts  int       `json:"max_attempts"`
	ImageDataURI string    `json:"image_data_uri"`
}

type storedChallenge struct {
	ID           string    `json:"id"`
	SessionID    string    `json:"session_id"`
	AnswerHash   []byte    `json:"answer_hash"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Attempts     int       `json:"attempts"`
	MaxAttempts  int       `json:"max_attempts"`
	ImageDataURI string    `json:"image_data_uri"`
}

// String implements fmt.Stringer for CaptchaChallenge, masking the SessionID
// and truncating the ImageDataURI to prevent leaking secrets into logs.
func (c CaptchaChallenge) String() string {
	imgPreview := c.ImageDataURI
	if len(imgPreview) > 32 {
		imgPreview = imgPreview[:32] + "..."
	}
	return fmt.Sprintf("CaptchaChallenge{ID:%s, Session:%s, Attempts:%d/%d, ExpiresAt:%s, Image:%s}",
		c.ID, MaskSessionID(c.SessionID), c.Attempts, c.MaxAttempts, c.ExpiresAt.Format(time.RFC3339), imgPreview)
}

// GoString implements fmt.GoStringer for CaptchaChallenge.
func (c CaptchaChallenge) GoString() string { return c.String() }

type ChallengeService interface {
	Issue(ctx context.Context, sessionID string) (*CaptchaChallenge, error)
	Validate(ctx context.Context, sessionID string, answer string) error
}

type challengeService struct {
	cfg   Config
	store store.Store
	clock Clock
}

func NewChallengeService(cfg Config, s store.Store, clock Clock) *challengeService {
	if clock == nil {
		clock = RealClock{}
	}
	return &challengeService{cfg: cfg, store: s, clock: clock}
}

func challengeKey(id string) string { return "challenge:" + id }

func (cs *challengeService) Issue(ctx context.Context, sessionID string) (*CaptchaChallenge, error) {
	if cs == nil || cs.store == nil {
		return nil, store.ErrStoreClosed
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, err
	}
	var out *CaptchaChallenge
	err := withSessionLock(ctx, cs.store, sessionID, func() error {
		sess, err := GetSession(ctx, cs.store, sessionID)
		if err != nil {
			return err
		}
		if sess.State != StateChallengeRequired {
			return ErrInvalidTransition
		}
		now := cs.clock.Now()
		if sess.IsExpired(now) {
			return ErrSessionExpired
		}
		if sess.ChallengeID != "" {
			if ch, err := cs.loadPublicChallenge(ctx, sess.ChallengeID, now); err == nil {
				out = ch
				return nil
			}
		}
		answer, err := randomCaptchaAnswer(cs.cfg.Captcha.Alphabet, cs.cfg.Captcha.Length)
		if err != nil {
			return err
		}
		id, err := GenerateSessionID()
		if err != nil {
			return err
		}
		pngData, err := renderCaptchaPNG(answer, cs.cfg.Captcha)
		if err != nil {
			return err
		}
		dataURI := captchaDataURI(pngData)
		st := storedChallenge{
			ID: id, SessionID: sessionID, AnswerHash: sha256Bytes(answer), CreatedAt: now,
			ExpiresAt: now.Add(cs.cfg.Captcha.TTL), Attempts: 0, MaxAttempts: cs.cfg.Captcha.MaxAttempts,
			ImageDataURI: dataURI,
		}
		data, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if len(data) > cs.cfg.StoreConfig.MaxValueBytes {
			return store.ErrValueTooLarge
		}
		ttl := st.ExpiresAt.Sub(now)
		if !sess.ExpiresAt.IsZero() && sess.ExpiresAt.Before(st.ExpiresAt) {
			ttl = sess.ExpiresAt.Sub(now)
		}
		if ttl <= 0 {
			return ErrSessionExpired
		}
		if err := cs.store.Set(ctx, challengeKey(id), data, ttl); err != nil {
			return err
		}
		sess.ChallengeID = id
		sttl := remainingTTL(sess, now, ttl)
		if sttl > ttl {
			sttl = ttl
		}
		if err := SaveSession(ctx, cs.store, sess, sttl); err != nil {
			_ = cs.store.Delete(context.Background(), challengeKey(id))
			return err
		}
		out = &CaptchaChallenge{ID: id, SessionID: sessionID, CreatedAt: st.CreatedAt, ExpiresAt: st.ExpiresAt, Attempts: 0, MaxAttempts: st.MaxAttempts, ImageDataURI: st.ImageDataURI}
		return nil
	})
	return out, err
}

func (cs *challengeService) loadPublicChallenge(ctx context.Context, id string, now time.Time) (*CaptchaChallenge, error) {
	data, err := cs.store.Get(ctx, challengeKey(id))
	if err != nil {
		return nil, err
	}
	var st storedChallenge
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	if !now.Before(st.ExpiresAt) {
		return nil, ErrChallengeExpired
	}
	return &CaptchaChallenge{ID: st.ID, SessionID: st.SessionID, CreatedAt: st.CreatedAt, ExpiresAt: st.ExpiresAt, Attempts: st.Attempts, MaxAttempts: st.MaxAttempts, ImageDataURI: st.ImageDataURI}, nil
}

func (cs *challengeService) Validate(ctx context.Context, sessionID string, answer string) error {
	if cs == nil || cs.store == nil {
		return store.ErrStoreClosed
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return err
	}
	if len(answer) > cs.cfg.MaxCookieValueBytes {
		return ErrChallengeFailed
	}
	answer = strings.ToUpper(strings.TrimSpace(answer))
	if answer == "" || len(answer) > cs.cfg.Captcha.Length {
		return ErrChallengeFailed
	}
	return withSessionLock(ctx, cs.store, sessionID, func() error {
		sess, err := GetSession(ctx, cs.store, sessionID)
		if err != nil {
			return err
		}
		if sess.State != StateChallengeRequired {
			return ErrInvalidTransition
		}
		if sess.ChallengeID == "" {
			return ErrChallengeNotFound
		}
		data, err := cs.store.Get(ctx, challengeKey(sess.ChallengeID))
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrChallengeNotFound
			}
			return err
		}
		var ch storedChallenge
		if err := json.Unmarshal(data, &ch); err != nil {
			return err
		}
		now := cs.clock.Now()
		if !now.Before(ch.ExpiresAt) {
			_ = cs.store.Delete(ctx, challengeKey(ch.ID))
			return ErrChallengeExpired
		}
		got := sha256Bytes(answer)
		if len(got) != len(ch.AnswerHash) || subtle.ConstantTimeCompare(got, ch.AnswerHash) != 1 {
			ch.Attempts++
			if ch.Attempts >= ch.MaxAttempts {
				_ = cs.store.Delete(ctx, challengeKey(ch.ID))
				sess.ChallengeID = ""
				if cs.cfg.WaitRoom.Enabled {
					sess.State = StateWaiting
					sess.FirstSeen = now
					ttl := cs.cfg.WaitRoom.WaitTime + 10*time.Minute
					if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(now.Add(ttl)) {
						ttl = sess.AbsoluteExpiresAt.Sub(now)
					}
					if ttl > 0 {
						sess.ExpiresAt = now.Add(ttl)
					}
				}
				if err := SaveSession(ctx, cs.store, sess, remainingTTL(sess, now, cs.cfg.SessionTTL)); err != nil {
					return err
				}
				return ErrMaxAttemptsExceeded
			}
			encoded, err := json.Marshal(ch)
			if err != nil {
				return err
			}
			ttl := ch.ExpiresAt.Sub(now)
			if ttl <= 0 {
				return ErrChallengeExpired
			}
			if err := cs.store.Set(ctx, challengeKey(ch.ID), encoded, ttl); err != nil {
				return err
			}
			return ErrChallengeFailed
		}
		if err := cs.store.Delete(ctx, challengeKey(ch.ID)); err != nil {
			return err
		}
		sess.ChallengeID = ""
		sess.State = StateAdmitted
		sess.LastSeenAt = now
		sess.ExpiresAt = now.Add(cs.cfg.SessionTTL)
		if !sess.AbsoluteExpiresAt.IsZero() && sess.AbsoluteExpiresAt.Before(sess.ExpiresAt) {
			sess.ExpiresAt = sess.AbsoluteExpiresAt
		}
		ttl := sess.ExpiresAt.Sub(now)
		if ttl <= 0 {
			return ErrSessionExpired
		}
		if err := SaveSession(ctx, cs.store, sess, ttl); err != nil {
			// Fail closed, but restore the single-use challenge so a transient store
			// failure does not permanently strand the session in CHALLENGE_REQUIRED.
			restoreTTL := ch.ExpiresAt.Sub(now)
			if restoreTTL > 0 {
				if raw, marshalErr := json.Marshal(ch); marshalErr == nil {
					_ = cs.store.Set(context.Background(), challengeKey(ch.ID), raw, restoreTTL)
				}
			}
			return err
		}
		if reservations, ok := cs.store.(store.SessionReservationStore); ok && cs.cfg.MaxConcurrentSessions > 0 {
			_, _ = reservations.ReserveSession(ctx, sessionCapacityKey, sess.SessionID, cs.cfg.MaxConcurrentSessions, sess.ExpiresAt)
		}
		return nil
	})
}

func sha256Bytes(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func (cs *challengeService) Get(ctx context.Context, sessionID string) (*CaptchaChallenge, error) {
	if cs == nil || cs.store == nil {
		return nil, store.ErrStoreClosed
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, err
	}
	sess, err := GetSession(ctx, cs.store, sessionID)
	if err != nil {
		return nil, err
	}
	if sess.ChallengeID == "" {
		return nil, ErrChallengeNotFound
	}
	return cs.loadPublicChallenge(ctx, sess.ChallengeID, cs.clock.Now())
}

var _ ChallengeService = (*challengeService)(nil)
