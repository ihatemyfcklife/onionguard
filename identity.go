package onionguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ihatemyfcklife/onionguard/store"
)

// IdentityKind classifies the confidence tier of a requesting entity.
type IdentityKind int

const (
	// IdentityAuthenticated represents a client whose identity is established
	// via upstream trusted authentication (e.g. client TLS cert, reverse proxy header).
	IdentityAuthenticated IdentityKind = iota + 1

	// IdentityAPIToken represents an automated client presenting a valid API bearer token or key.
	IdentityAPIToken

	// IdentityAnonymous represents a human or automated Tor visitor with an active, admitted session.
	IdentityAnonymous

	// IdentityAnonymousNew represents a newly arrived visitor or unadmitted session in the wait room / challenge.
	IdentityAnonymousNew
)

// String returns the canonical name of the identity kind.
func (k IdentityKind) String() string {
	switch k {
	case IdentityAuthenticated:
		return "Authenticated"
	case IdentityAPIToken:
		return "APIToken"
	case IdentityAnonymous:
		return "Anonymous"
	case IdentityAnonymousNew:
		return "AnonymousNew"
	default:
		return fmt.Sprintf("IdentityKind(%d)", k)
	}
}

// ClientIdentity captures the resolved identity and metadata for a request.
type ClientIdentity struct {
	Kind        IdentityKind `json:"kind"`
	PrincipalID string       `json:"principal_id,omitempty"`
	TokenHash   string       `json:"token_hash,omitempty"` // Truncated SHA-256 for rate limiting
	SessionID   string       `json:"session_id,omitempty"` // Opaque session ID for anonymous clients
}

// String returns a redacted, safe representation of ClientIdentity (Invariants 1, 24).
func (ci ClientIdentity) String() string {
	var maskedSession string
	if ci.SessionID != "" {
		maskedSession = MaskSessionID(ci.SessionID)
	}
	principal := ci.PrincipalID
	if (ci.Kind == IdentityAnonymous || ci.Kind == IdentityAnonymousNew) && principal != "" {
		principal = MaskSessionID(principal)
	}
	return fmt.Sprintf("ClientIdentity{Kind:%s, PrincipalID:%q, TokenHash:%q, SessionID:%q}",
		ci.Kind, principal, ci.TokenHash, maskedSession)
}

// GoString redacts sensitive fields for %#v formatters.
func (ci ClientIdentity) GoString() string {
	return ci.String()
}

// IsAdmitted returns true if the client is authorized to bypass friction and reach backend handlers.
func (ci ClientIdentity) IsAdmitted() bool {
	return ci.Kind == IdentityAuthenticated || ci.Kind == IdentityAPIToken || ci.Kind == IdentityAnonymous
}

// RateLimitKey returns the identity-bound key for token bucket rate limiting (Invariant 25).
// Rate limits NEVER use client IP addresses (Invariants 26, 27, 28).
func (ci ClientIdentity) RateLimitKey() string {
	switch ci.Kind {
	case IdentityAuthenticated:
		return "auth:" + ci.PrincipalID
	case IdentityAPIToken:
		if ci.TokenHash != "" {
			return "token:" + ci.TokenHash
		}
		return "token:" + ci.PrincipalID
	case IdentityAnonymous:
		return "anon:" + MaskSessionID(ci.SessionID)
	case IdentityAnonymousNew:
		if ci.SessionID != "" {
			return "anon_new:" + MaskSessionID(ci.SessionID)
		}
		return "anon_new:global"
	default:
		return "unknown:global"
	}
}

// RateLimitScope maps the identity tier to its configured RateLimitScope.
func (ci ClientIdentity) RateLimitScope() RateLimitScope {
	switch ci.Kind {
	case IdentityAuthenticated:
		return ScopeAuthenticated
	case IdentityAPIToken:
		return ScopeAPIToken
	case IdentityAnonymous:
		return ScopeAnonymous
	case IdentityAnonymousNew:
		return ScopeAnonymous
	default:
		return ScopeAnonymous
	}
}

// TokenValidator validates raw API tokens presented in requests.
type TokenValidator interface {
	ValidateToken(ctx context.Context, rawToken string) (principal string, ok bool, err error)
}

// TokenValidatorFunc allows using a function as a TokenValidator.
type TokenValidatorFunc func(ctx context.Context, rawToken string) (string, bool, error)

// ValidateToken calls the underlying function.
func (f TokenValidatorFunc) ValidateToken(ctx context.Context, rawToken string) (string, bool, error) {
	return f(ctx, rawToken)
}

// PrincipalExtractor extracts pre-authenticated principal information from an HTTP request.
type PrincipalExtractor interface {
	ExtractPrincipal(r *http.Request) (principal string, ok bool)
}

// PrincipalExtractorFunc allows using a function as a PrincipalExtractor.
type PrincipalExtractorFunc func(r *http.Request) (string, bool)

// ExtractPrincipal calls the underlying function.
func (f PrincipalExtractorFunc) ExtractPrincipal(r *http.Request) (string, bool) {
	return f(r)
}

// contextKey defines an unexported key type for storing ClientIdentity in context.
type identityContextKeyType struct{}

var identityContextKey = identityContextKeyType{}

// WithClientIdentity returns a new context containing the resolved ClientIdentity.
func WithClientIdentity(ctx context.Context, id ClientIdentity) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// ClientIdentityFromContext extracts ClientIdentity from context if present.
func ClientIdentityFromContext(ctx context.Context) (ClientIdentity, bool) {
	id, ok := ctx.Value(identityContextKey).(ClientIdentity)
	return id, ok
}

// IdentityResolver coordinates identity resolution across all 4 tiers.
type IdentityResolver struct {
	config             Config
	store              store.Store
	clock              Clock
	tokenValidator     TokenValidator
	principalExtractor PrincipalExtractor
}

// NewIdentityResolver creates an initialized IdentityResolver.
func NewIdentityResolver(cfg Config, s store.Store, clock Clock, tv TokenValidator, pe PrincipalExtractor) *IdentityResolver {
	if clock == nil {
		clock = RealClock{}
	}
	return &IdentityResolver{
		config:             cfg,
		store:              s,
		clock:              clock,
		tokenValidator:     tv,
		principalExtractor: pe,
	}
}

func (ir *IdentityResolver) now() time.Time {
	if ir != nil && ir.clock != nil {
		return ir.clock.Now()
	}
	return time.Now()
}

// Resolve extracts and classifies identity following the strict priority sequence:
// 1. Authenticated Principal -> 2. API Token -> 3. Existing Anonymous Session -> 4. New Anonymous.
// Client IP headers (RemoteAddr, X-Forwarded-For, X-Real-IP) are completely ignored (Invariants 25-28).
func (ir *IdentityResolver) Resolve(r *http.Request) (ClientIdentity, error) {
	id, _, err := ir.ResolveWithSession(r)
	return id, err
}

// ResolveWithSession resolves client identity and returns any existing session snapshot retrieved
// from storage during resolution, eliminating redundant store lookups downstream.
func (ir *IdentityResolver) ResolveWithSession(r *http.Request) (ClientIdentity, *Session, error) {
	if ir == nil {
		return ClientIdentity{}, nil, ErrEngineNotInitialized
	}
	if r == nil {
		return ClientIdentity{}, nil, ErrInvalidSession
	}
	ctx := r.Context()

	// 1. Authenticated Principal (Priority 1)
	if ir.principalExtractor != nil {
		if principal, ok := ir.principalExtractor.ExtractPrincipal(r); ok && principal != "" {
			if len(principal) > ir.config.MaxPrincipalIDBytes {
				return ClientIdentity{}, nil, ErrInvalidToken
			}
			return ClientIdentity{
				Kind:        IdentityAuthenticated,
				PrincipalID: principal,
			}, nil, nil
		}
	}

	// 2. API Token (Priority 2)
	rawToken := extractAPIToken(r, ir.config)
	if rawToken != "" {
		if len(rawToken) > ir.config.MaxTokenBytes {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		if ir.tokenValidator == nil {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		principal, ok, err := ir.tokenValidator.ValidateToken(ctx, rawToken)
		if err != nil {
			return ClientIdentity{}, nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		if !ok {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		if principal == "" || len(principal) > ir.config.MaxPrincipalIDBytes {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		h := sha256.Sum256([]byte(rawToken))
		tokenHash := hex.EncodeToString(h[:8])
		return ClientIdentity{
			Kind:        IdentityAPIToken,
			PrincipalID: principal,
			TokenHash:   tokenHash,
		}, nil, nil
	}

	// 3. Existing Anonymous Session (Priority 3)
	cookie, err := r.Cookie(ir.config.SessionCookieName)
	if err == nil && cookie != nil && cookie.Value != "" {
		if len(cookie.Value) > ir.config.MaxCookieValueBytes {
			return ClientIdentity{}, nil, ErrInvalidSession
		}
		cookieVal := strings.TrimSpace(cookie.Value)
		if err := ValidateSessionID(cookieVal); err == nil && ir.store != nil {
			sess, err := GetSession(ctx, ir.store, cookieVal)
			if err != nil && !errors.Is(err, ErrInvalidSession) {
				return ClientIdentity{}, nil, err
			}
			if err == nil && sess != nil {
				if sess.State == StateAdmitted && !sess.IsExpired(ir.now()) && !sess.IsRevoked() {
					return ClientIdentity{
						Kind:        IdentityAnonymous,
						PrincipalID: sess.SessionID,
						SessionID:   sess.SessionID,
					}, sess, nil
				}
				// Session is pending, expired, or revoked - return with SessionID so state machine handles it
				return ClientIdentity{
					Kind:        IdentityAnonymousNew,
					PrincipalID: sess.SessionID,
					SessionID:   sess.SessionID,
				}, sess, nil
			}
		}
	}

	// 4. New Anonymous Visitor (Priority 4)
	return ClientIdentity{
		Kind: IdentityAnonymousNew,
	}, nil, nil
}

// ResolveRaw extracts identity from pre-copied scalar strings (used by Fiber v2 adapter and tests).
func (ir *IdentityResolver) ResolveRaw(ctx context.Context, principal, authHeader, apiKeyHeader, queryToken, cookieVal string) (ClientIdentity, error) {
	id, _, err := ir.ResolveRawWithSession(ctx, principal, authHeader, apiKeyHeader, queryToken, cookieVal)
	return id, err
}

// ResolveRawWithSession extracts identity from pre-copied scalar strings and returns any retrieved session.
func (ir *IdentityResolver) ResolveRawWithSession(ctx context.Context, principal, authHeader, apiKeyHeader, queryToken, cookieVal string) (ClientIdentity, *Session, error) {
	// 1. Authenticated Principal
	if principal != "" {
		if len(principal) > ir.config.MaxPrincipalIDBytes {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		return ClientIdentity{
			Kind:        IdentityAuthenticated,
			PrincipalID: principal,
		}, nil, nil
	}

	// 2. API Token
	rawToken := extractAPITokenRaw(authHeader, apiKeyHeader, queryToken, ir.config)
	if rawToken != "" {
		if len(rawToken) > ir.config.MaxTokenBytes {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		if ir.tokenValidator == nil {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		p, ok, err := ir.tokenValidator.ValidateToken(ctx, rawToken)
		if err != nil {
			return ClientIdentity{}, nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
		}
		if !ok {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		if p == "" || len(p) > ir.config.MaxPrincipalIDBytes {
			return ClientIdentity{}, nil, ErrInvalidToken
		}
		h := sha256.Sum256([]byte(rawToken))
		tokenHash := hex.EncodeToString(h[:8])
		return ClientIdentity{
			Kind:        IdentityAPIToken,
			PrincipalID: p,
			TokenHash:   tokenHash,
		}, nil, nil
	}

	// 3. Existing Anonymous Session
	if cookieVal != "" && ir.store != nil {
		if len(cookieVal) > ir.config.MaxCookieValueBytes {
			return ClientIdentity{}, nil, ErrInvalidSession
		}
		cookieVal = strings.TrimSpace(cookieVal)
		if err := ValidateSessionID(cookieVal); err == nil {
			sess, err := GetSession(ctx, ir.store, cookieVal)
			if err != nil && !errors.Is(err, ErrInvalidSession) {
				return ClientIdentity{}, nil, err
			}
			if err == nil && sess != nil {
				if sess.State == StateAdmitted && !sess.IsExpired(ir.now()) && !sess.IsRevoked() {
					return ClientIdentity{
						Kind:        IdentityAnonymous,
						PrincipalID: sess.SessionID,
						SessionID:   sess.SessionID,
					}, sess, nil
				}
				return ClientIdentity{
					Kind:        IdentityAnonymousNew,
					PrincipalID: sess.SessionID,
					SessionID:   sess.SessionID,
				}, sess, nil
			}
		}
	}

	// 4. New Anonymous
	return ClientIdentity{
		Kind: IdentityAnonymousNew,
	}, nil, nil
}

// extractAPIToken retrieves the token from the configured Authorization header, or from the query only when explicitly enabled.
func extractAPIToken(r *http.Request, cfg Config) string {
	headerName := cfg.APITokenHeader
	if headerName == "" {
		headerName = "Authorization"
	}
	authHeader := r.Header.Get(headerName)
	var queryToken string
	if cfg.AllowURLToken && r.URL != nil {
		queryToken = r.URL.Query().Get("token")
		if queryToken == "" {
			queryToken = r.URL.Query().Get("api_key")
		}
	}
	return extractAPITokenRaw(authHeader, "", queryToken, cfg)
}

// extractAPITokenRaw extracts API token strings with strict rejection of URL query tokens by default (Invariant 22).
func extractAPITokenRaw(authHeader, apiKeyHeader, queryToken string, cfg Config) string {
	if authHeader != "" {
		prefix := cfg.APITokenPrefix
		if prefix != "" {
			if strings.HasPrefix(strings.ToLower(authHeader), strings.ToLower(prefix)) {
				token := strings.TrimSpace(authHeader[len(prefix):])
				if token != "" {
					return token
				}
			}
		} else {
			token := strings.TrimSpace(authHeader)
			if token != "" {
				return token
			}
		}
	}

	// apiKeyHeader is retained only for explicit ResolveRaw callers that already
	// separated the transport layer. The built-in net/http/Fiber resolvers do
	// not read X-API-Key by default.
	if apiKeyHeader != "" {
		token := strings.TrimSpace(apiKeyHeader)
		if token != "" {
			return token
		}
	}

	if cfg.AllowURLToken && queryToken != "" {
		token := strings.TrimSpace(queryToken)
		if token != "" {
			return token
		}
	}

	return ""
}
