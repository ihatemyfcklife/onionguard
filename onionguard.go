package onionguard

import (
	"context"
	"errors"
	"net/http"
	"time"

	"onionguard/store"
)

type Engine struct {
	cfg                Config
	store              store.Store
	ownStore           bool
	admission          *AdmissionEngine
	identity           *IdentityResolver
	challenge          *challengeService
	rateLimiter        *RateLimiter
	tokenValidator     TokenValidator
	principalExtractor PrincipalExtractor
	metrics            MetricsObserver
}

// MetricsObserver is an optional observer interface for monitoring OnionGuard operations.
// Implementations MUST NOT log or expose raw session IDs or identity tokens to preserve anonymity.
type MetricsObserver interface {
	OnRequestAdmitted(kind IdentityKind)
	OnWaitRoomQueued(waitTime time.Duration)
	OnChallengeIssued()
	OnChallengeSolved()
	OnChallengeFailed()
	OnRateLimited(kind IdentityKind)
}

// NoopMetricsObserver implements MetricsObserver with no-op methods.
type NoopMetricsObserver struct{}

func (NoopMetricsObserver) OnRequestAdmitted(IdentityKind) {}
func (NoopMetricsObserver) OnWaitRoomQueued(time.Duration) {}
func (NoopMetricsObserver) OnChallengeIssued()             {}
func (NoopMetricsObserver) OnChallengeSolved()             {}
func (NoopMetricsObserver) OnChallengeFailed()             {}
func (NoopMetricsObserver) OnRateLimited(IdentityKind)     {}

type EngineOption func(*Engine)

func WithTokenValidator(v TokenValidator) EngineOption {
	return func(e *Engine) { e.tokenValidator = v }
}
func WithPrincipalExtractor(v PrincipalExtractor) EngineOption {
	return func(e *Engine) { e.principalExtractor = v }
}
func WithMetricsObserver(m MetricsObserver) EngineOption {
	return func(e *Engine) { e.metrics = m }
}

func New(cfg Config, opts ...EngineOption) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	e := &Engine{cfg: cfg}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	if cfg.Store != nil {
		e.store = cfg.Store
	} else {
		var err error
		switch cfg.StoreConfig.Type {
		case StoreTypeMemory, "":
			e.store, err = store.NewMemoryStore(store.MemoryConfig{
				Clock:           cfg.Clock,
				MaxEntries:      cfg.StoreConfig.MaxEntries,
				MaxKeyBytes:     cfg.StoreConfig.MaxKeyBytes,
				MaxValueBytes:   cfg.StoreConfig.MaxValueBytes,
				CleanupInterval: cfg.StoreConfig.CleanupInterval,
			})
			e.ownStore = true
		case StoreTypeRedis:
			e.store, err = store.NewRedisStore(store.RedisConfig{
				Addr:          cfg.StoreConfig.RedisAddr,
				Password:      cfg.StoreConfig.RedisPassword,
				DB:            cfg.StoreConfig.RedisDB,
				Prefix:        cfg.StoreConfig.RedisPrefix,
				DialTimeout:   cfg.StoreConfig.RedisDialTimeout,
				FailClosed:    cfg.StoreConfig.RedisFailClosed,
				MaxKeyBytes:   cfg.StoreConfig.MaxKeyBytes,
				MaxValueBytes: cfg.StoreConfig.MaxValueBytes,
				PoolSize:      cfg.StoreConfig.RedisPoolSize,
				MinIdleConns:  cfg.StoreConfig.RedisMinIdleConns,
				MaxRetries:    cfg.StoreConfig.RedisMaxRetries,
				ReadTimeout:   cfg.StoreConfig.RedisReadTimeout,
				WriteTimeout:  cfg.StoreConfig.RedisWriteTimeout,
				PoolTimeout:   cfg.StoreConfig.RedisPoolTimeout,
			})
			e.ownStore = true
		default:
			return nil, errors.New("onionguard: unsupported store type")
		}
		if err != nil {
			return nil, err
		}
	}
	if setter, ok := e.store.(store.ClockSetter); ok && cfg.Clock != nil {
		setter.SetClock(cfg.Clock)
	}
	e.cfg.Store = e.store
	e.admission = NewAdmissionEngine(cfg, e.store, cfg.Clock)
	e.identity = NewIdentityResolver(cfg, e.store, cfg.Clock, e.tokenValidator, e.principalExtractor)
	e.challenge = NewChallengeService(cfg, e.store, cfg.Clock)
	e.rateLimiter = NewRateLimiter(cfg, e.store, cfg.Clock)
	return e, nil
}

func NewEngine(cfg Config, opts ...EngineOption) (*Engine, error) { return New(cfg, opts...) }

func (e *Engine) Config() Config {
	if e == nil {
		return Config{}
	}
	return e.cfg
}
func (e *Engine) Store() store.Store {
	if e == nil {
		return nil
	}
	return e.store
}
func (e *Engine) Metrics() MetricsObserver {
	if e == nil {
		return nil
	}
	return e.metrics
}

// Ping checks the health of the underlying store and engine subsystem.
func (e *Engine) Ping(ctx context.Context) error {
	if e == nil {
		return ErrEngineNotInitialized
	}
	if e.store == nil {
		return ErrStoreNotConfigured
	}
	if pinger, ok := e.store.(store.Pinger); ok {
		return pinger.Ping(ctx)
	}
	return nil
}

func (e *Engine) Close() error {
	if e == nil || e.store == nil || !e.ownStore {
		return nil
	}
	return e.store.Close()
}

type RequestDecision struct {
	Identity  ClientIdentity
	Admission AdmissionDecision
	Session   *Session
	Challenge *CaptchaChallenge
	RateLimit RateLimitResult
}

func (e *Engine) AuthorizeRequest(ctx context.Context, r *http.Request) (RequestDecision, error) {
	return e.authorizeRequest(ctx, r, 0)
}

// AuthorizeRequestWithCost applies an operation-specific rate-limit cost in a single admission evaluation.
// A zero or negative cost uses the configured rule cost.
func (e *Engine) AuthorizeRequestWithCost(ctx context.Context, r *http.Request, cost int64) (RequestDecision, error) {
	return e.authorizeRequest(ctx, r, cost)
}

func (e *Engine) authorizeRequest(ctx context.Context, r *http.Request, cost int64) (RequestDecision, error) {
	if e == nil || e.identity == nil || e.admission == nil {
		return RequestDecision{}, ErrEngineNotInitialized
	}
	if r == nil {
		return RequestDecision{}, ErrInvalidSession
	}
	id, sess, err := e.identity.ResolveWithSession(r)
	if err != nil {
		return RequestDecision{Identity: id}, err
	}
	if id.Kind == IdentityAuthenticated || id.Kind == IdentityAPIToken {
		rl, err := e.rateLimiter.Allow(ctx, id, r.Method+":"+r.URL.Path, cost)
		if err != nil {
			if errors.Is(err, ErrRateLimited) && e.metrics != nil {
				e.metrics.OnRateLimited(id.Kind)
			}
			return RequestDecision{Identity: id, RateLimit: rl}, e.handleBackendError(err, true)
		}
		if e.metrics != nil {
			e.metrics.OnRequestAdmitted(id.Kind)
		}
		return RequestDecision{Identity: id, RateLimit: rl, Admission: AdmissionDecision{Allowed: true, State: StateAdmitted}}, nil
	}
	var rl RateLimitResult
	if id.SessionID == "" {
		// First contact: evaluate rate limit against unassigned visitor pool first,
		// preventing resource exhaustion via rapid session creation.
		var rlErr error
		rl, rlErr = e.rateLimiter.Allow(ctx, id, r.Method+":"+r.URL.Path, cost)
		if rlErr != nil {
			if errors.Is(rlErr, ErrRateLimited) && e.metrics != nil {
				e.metrics.OnRateLimited(id.Kind)
			}
			return RequestDecision{Identity: id, RateLimit: rl}, e.handleBackendError(rlErr, true)
		}
		// Create exactly one in-memory session candidate. It is
		// persisted by the admission engine when it enters a real state.
		sess, err = NewSession(e.cfg.Clock.Now(), e.cfg.MaxRenewals)
		if err != nil {
			return RequestDecision{Identity: id, RateLimit: rl}, err
		}
		id.SessionID = sess.SessionID
		id.PrincipalID = sess.SessionID
		id.Kind = IdentityAnonymousNew
	} else if sess == nil {
		sess, err = GetSession(ctx, e.store, id.SessionID)
		if err != nil {
			if !errors.Is(err, ErrInvalidSession) {
				return RequestDecision{Identity: id}, e.handleBackendError(err, true)
			}
			// Invalid/missing cookie: rate limit against unassigned pool
			idGlobal := ClientIdentity{Kind: IdentityAnonymousNew}
			var rlErr error
			rl, rlErr = e.rateLimiter.Allow(ctx, idGlobal, r.Method+":"+r.URL.Path, cost)
			if rlErr != nil {
				if errors.Is(rlErr, ErrRateLimited) && e.metrics != nil {
					e.metrics.OnRateLimited(idGlobal.Kind)
				}
				return RequestDecision{Identity: idGlobal, RateLimit: rl}, e.handleBackendError(rlErr, true)
			}
			// Bootstrap a fresh anonymous session.
			sess, err = NewSession(e.cfg.Clock.Now(), e.cfg.MaxRenewals)
			if err != nil {
				return RequestDecision{Identity: idGlobal, RateLimit: rl}, err
			}
			id.SessionID = sess.SessionID
			id.PrincipalID = sess.SessionID
			id.Kind = IdentityAnonymousNew
		} else {
			// Existing session in store: rate limit against this specific session
			var rlErr error
			rl, rlErr = e.rateLimiter.Allow(ctx, id, r.Method+":"+r.URL.Path, cost)
			if rlErr != nil {
				if errors.Is(rlErr, ErrRateLimited) && e.metrics != nil {
					e.metrics.OnRateLimited(id.Kind)
				}
				return RequestDecision{Identity: id, Session: sess, RateLimit: rl}, e.handleBackendError(rlErr, true)
			}
		}
	} else {
		// Existing session already retrieved by ResolveWithSession: rate limit against this specific session
		var rlErr error
		rl, rlErr = e.rateLimiter.Allow(ctx, id, r.Method+":"+r.URL.Path, cost)
		if rlErr != nil {
			if errors.Is(rlErr, ErrRateLimited) && e.metrics != nil {
				e.metrics.OnRateLimited(id.Kind)
			}
			return RequestDecision{Identity: id, Session: sess, RateLimit: rl}, e.handleBackendError(rlErr, true)
		}
	}
	dec, err := e.admission.EvaluateFresh(ctx, sess)
	if err != nil {
		return RequestDecision{Identity: id, Session: dec.Session, Admission: dec, RateLimit: rl}, e.handleBackendError(err, true)
	}
	result := RequestDecision{Identity: id, Session: dec.Session, Admission: dec, RateLimit: rl}
	if dec.Allowed {
		result.Identity.Kind = IdentityAnonymous
		result.Identity.SessionID = dec.Session.SessionID
		result.Identity.PrincipalID = dec.Session.SessionID
		if e.metrics != nil {
			e.metrics.OnRequestAdmitted(result.Identity.Kind)
		}
		return result, nil
	}
	if dec.State == StateWaiting {
		if e.metrics != nil {
			e.metrics.OnWaitRoomQueued(dec.RetryAfter)
		}
	}
	if dec.State == StateChallengeRequired && e.cfg.Captcha.Enabled && dec.Session != nil {
		ch, err := e.challenge.Issue(ctx, dec.Session.SessionID)
		if err != nil {
			return result, e.handleBackendError(err, true)
		}
		if e.metrics != nil {
			e.metrics.OnChallengeIssued()
		}
		result.Challenge = ch
		result.Admission.ChallengeID = ch.ID
	}
	return result, nil
}

func (e *Engine) handleBackendError(err error, critical bool) error {
	if err == nil {
		return nil
	}
	if !critical {
		return nil
	}
	// Store failure policy applies at the transport layer; the secure default is fail-closed.
	return err
}

func (e *Engine) IssueChallenge(ctx context.Context, sessionID string) (*CaptchaChallenge, error) {
	if e == nil || e.challenge == nil {
		return nil, ErrEngineNotInitialized
	}
	ch, err := e.challenge.Issue(ctx, sessionID)
	if err == nil && e.metrics != nil {
		e.metrics.OnChallengeIssued()
	}
	return ch, err
}
func (e *Engine) ValidateChallenge(ctx context.Context, sessionID, answer string) error {
	if e == nil || e.challenge == nil {
		return ErrEngineNotInitialized
	}
	err := e.challenge.Validate(ctx, sessionID, answer)
	if e.metrics != nil {
		if err != nil {
			e.metrics.OnChallengeFailed()
		} else {
			e.metrics.OnChallengeSolved()
		}
	}
	return err
}
func (e *Engine) GetChallenge(ctx context.Context, sessionID string) (*CaptchaChallenge, error) {
	if e == nil || e.challenge == nil {
		return nil, ErrEngineNotInitialized
	}
	return e.challenge.Get(ctx, sessionID)
}

func (e *Engine) SessionCookie(sess *Session) *http.Cookie {
	if e == nil || sess == nil || sess.SessionID == "" {
		return nil
	}
	now := time.Now()
	if e.cfg.Clock != nil {
		now = e.cfg.Clock.Now()
	}
	if sess.IsRevoked() || sess.IsExpired(now) {
		return &http.Cookie{
			Name:     e.cfg.SessionCookieName,
			Value:    "",
			Path:     e.cfg.CookiePath,
			Domain:   e.cfg.CookieDomain,
			HttpOnly: e.cfg.CookieHTTPOnly,
			Secure:   e.cfg.CookieSecure,
			SameSite: e.cfg.CookieSameSite,
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
		}
	}
	maxAge := 0
	if !sess.ExpiresAt.IsZero() {
		seconds := int(sess.ExpiresAt.Sub(now).Seconds())
		if seconds > 0 {
			maxAge = seconds
		}
	}
	return &http.Cookie{Name: e.cfg.SessionCookieName, Value: sess.SessionID, Path: e.cfg.CookiePath, Domain: e.cfg.CookieDomain, HttpOnly: e.cfg.CookieHTTPOnly, Secure: e.cfg.CookieSecure, SameSite: e.cfg.CookieSameSite, MaxAge: maxAge}
}

func withIdentityContext(ctx context.Context, id ClientIdentity) context.Context {
	return WithClientIdentity(ctx, id)
}

type sessionContextKey struct{}

func WithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, sess)
}
func SessionFromContext(ctx context.Context) (*Session, bool) {
	sess, ok := ctx.Value(sessionContextKey{}).(*Session)
	return sess, ok
}

func (e *Engine) AllowRateLimit(ctx context.Context, id ClientIdentity, operation string, cost int64) (RateLimitResult, error) {
	if e == nil || e.rateLimiter == nil {
		return RateLimitResult{Allowed: true}, nil
	}
	return e.rateLimiter.Allow(ctx, id, operation, cost)
}

func (e *Engine) ResolveIdentity(r *http.Request) (ClientIdentity, error) {
	if e == nil || e.identity == nil {
		return ClientIdentity{}, ErrEngineNotInitialized
	}
	return e.identity.Resolve(r)
}

func (e *Engine) EvaluateSession(ctx context.Context, sess *Session) (AdmissionDecision, error) {
	if e == nil || e.admission == nil {
		return AdmissionDecision{}, ErrEngineNotInitialized
	}
	return e.admission.Evaluate(ctx, sess)
}

// RevokeSession marks an active session as revoked, terminating access and freeing reserved capacity.
func (e *Engine) RevokeSession(ctx context.Context, sessionID string) error {
	if e == nil {
		return ErrEngineNotInitialized
	}
	if e.store == nil {
		return ErrStoreNotConfigured
	}
	clock := e.cfg.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return RevokeSessionWithClock(ctx, e.store, sessionID, 5*time.Minute, clock)
}

// RotateSession generates a fresh session identifier for an admitted session,
// transferring its admission state and lifetime bounds atomically while invalidating the old token.
func (e *Engine) RotateSession(ctx context.Context, oldSessionID string) (*Session, error) {
	if e == nil {
		return nil, ErrEngineNotInitialized
	}
	if e.store == nil {
		return nil, ErrStoreNotConfigured
	}
	clock := e.cfg.Clock
	if clock == nil {
		clock = RealClock{}
	}
	return RotateSession(ctx, e.store, oldSessionID, e.cfg.SessionTTL, clock)
}
