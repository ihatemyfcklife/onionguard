package onionguard

import (
	"errors"
	"fmt"
	"image/color"
	"net/http"
	"time"

	"onionguard/store"
)

// HeaderPolicy defines coexistence behavior for HTTP security headers.
type HeaderPolicy int

const (
	HeaderPreserve HeaderPolicy = iota // Do not overwrite if header already present
	HeaderOverride                     // Overwrite existing header value
	HeaderMerge                        // Merge/append values (applicable to CSP)
)

// SecurityHeadersConfig holds HTTP security header settings.
type SecurityHeadersConfig struct {
	Policy                HeaderPolicy
	ContentSecurityPolicy string // default: "default-src 'none'; img-src data:; form-action 'self'"
	XContentTypeOptions   string // default: "nosniff"
	XFrameOptions         string // default: "DENY"
	ReferrerPolicy        string // default: "no-referrer"
}

// RateLimitRule defines token-bucket parameters for a protection scope.
type RateLimitRule struct {
	Rate   float64       // Tokens added per second
	Burst  int           // Maximum bucket capacity
	Cost   int64         // Tokens deducted per request (default: 1)
	Window time.Duration // Key TTL expiration window
}

// RateLimitScope designates the protection tier.
type RateLimitScope string

const (
	ScopeAnonymous     RateLimitScope = "anonymous"
	ScopeAuthenticated RateLimitScope = "authenticated"
	ScopeAPIToken      RateLimitScope = "api_token"
	ScopeChallenge     RateLimitScope = "challenge"
	ScopeFirstContact  RateLimitScope = "first_contact"
)

// RateLimitConfig holds multi-tier token bucket configuration.
type RateLimitConfig struct {
	Enabled bool
	Limits  map[RateLimitScope]RateLimitRule
}

// WaitRoomConfig configures the proof-of-patience wait room friction.
type WaitRoomConfig struct {
	Enabled  bool
	WaitTime time.Duration // default: 5s
}

// CaptchaVisualConfig controls the appearance of the generated CAPTCHA PNG image.
// All fields have sensible defaults when left at zero value.
type CaptchaVisualConfig struct {
	BackgroundColor color.Color // Background fill (default: RGBA{245, 245, 245, 255})
	TextColor       color.Color // Glyph ink color (default: RGBA{30, 30, 30, 255})
	LineColor       color.Color // Noise line color (default: RGBA{60, 60, 60, 200})
	NoiseLines      int         // Number of diagonal noise lines (default: 2; 0 disables)
	NoiseRatio      float64     // Background pixel noise density (default: 0.02 = 2%)
	JitterPixels    int         // Max vertical jitter per glyph in pixels (default: 2)

	// CustomGenerator replaces the built-in bitmap renderer entirely.
	// Use this to plug in a TTF/vector font renderer or an external CAPTCHA service.
	// When set, all other visual fields are ignored.
	CustomGenerator func(answer string, width, height int) ([]byte, error)
}

// CaptchaConfig configures the zero-JS pure Go CAPTCHA challenge engine.
type CaptchaConfig struct {
	Enabled      bool
	Length       int                 // Character count (default: 5)
	TTL          time.Duration       // Validity window (default: 3m)
	MaxAttempts  int                 // Max attempts before invalidation (default: 3)
	Width        int                 // Image width in pixels (default: 160)
	Height       int                 // Image height in pixels (default: 60)
	Alphabet     string              // Character set excluding ambiguous glyphs (default: "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
	EndpointPath string              // Path for challenge verification POST (default: "/onionguard/challenge")
	Visual       CaptchaVisualConfig // Visual appearance customization
}

// StoreType defines the storage backend category.
type StoreType string

const (
	StoreTypeMemory StoreType = "memory"
	StoreTypeRedis  StoreType = "redis"
)

// StoreConfig defines backend storage parameters.
type StoreConfig struct {
	Type            StoreType     // "memory" or "redis"
	MaxEntries      int           // MemoryStore max key count (default: 10,000)
	MaxKeyBytes     int           // Max key size in bytes (default: 256)
	MaxValueBytes   int           // Max value size in bytes (default: 65,536 = 64 KiB)
	CleanupInterval time.Duration // Janitor sweep interval (default: 30s)

	// Redis options
	RedisAddr         string        // e.g. "127.0.0.1:6379"
	RedisPassword     string        // Redacted in logs (Invariant 1)
	RedisDB           int           // Redis database index (default: 0)
	RedisPrefix       string        // Key prefix (default: "onionguard:")
	RedisFailClosed   bool          // If true, Redis errors halt requests (default: true, Invariant 14)
	RedisDialTimeout  time.Duration // Connection timeout (default: 2s)
	RedisPoolSize     int           // Max active socket connections (default: 10 * GOMAXPROCS)
	RedisMinIdleConns int           // Minimum idle connections (default: 0)
	RedisMaxRetries   int           // Max command retry attempts (default: 3)
	RedisReadTimeout  time.Duration // Socket read timeout (default: 2s)
	RedisWriteTimeout time.Duration // Socket write timeout (default: 2s)
	RedisPoolTimeout  time.Duration // Connection pool acquisition timeout (default: 3s)
}

// String redacts sensitive credentials (Invariant 1).
func (s StoreConfig) String() string {
	pwdDisplay := "[NONE]"
	if s.RedisPassword != "" {
		pwdDisplay = "[REDACTED]"
	}
	return fmt.Sprintf("StoreConfig{Type:%s, MaxEntries:%d, MaxKeyBytes:%d, MaxValueBytes:%d, RedisAddr:%s, RedisPassword:%s, FailClosed:%t}",
		s.Type, s.MaxEntries, s.MaxKeyBytes, s.MaxValueBytes, s.RedisAddr, pwdDisplay, s.RedisFailClosed)
}

// GoString redacts sensitive credentials for %#v formatting.
func (s StoreConfig) GoString() string {
	return s.String()
}

// Config represents the master configuration for OnionGuard.
type Config struct {
	// Storage instance (if already constructed, or initialized via StoreConfig)
	Store       store.Store
	StoreConfig StoreConfig

	// Sub-configurations
	WaitRoom        WaitRoomConfig
	Captcha         CaptchaConfig
	RateLimit       RateLimitConfig
	SecurityHeaders SecurityHeadersConfig

	// Session Management
	SessionCookieName       string
	SessionTTL              time.Duration
	CookieSecure            bool          // false for Tor .onion HTTP, true if TLS terminated
	CookieHTTPOnly          bool          // default: true
	CookieSameSite          http.SameSite // default: http.SameSiteLaxMode
	CookiePath              string        // default: "/"
	CookieDomain            string        // default: ""
	MaxRenewals             int           // default: 10
	MaxConcurrentSessions   int           // global session resource bound
	SessionAbsoluteLifetime time.Duration // default: 7 days; zero disables absolute lifetime

	// Request Limits
	MaxBodyBytes        int64 // default: 100 KiB (102400 bytes)
	MaxTokenBytes       int
	MaxCookieNameBytes  int
	MaxCookieValueBytes int
	MaxPrincipalIDBytes int
	MaxChallengeIDBytes int
	MaxStoreKeyBytes    int

	// Zero-Trust IP Configuration (Invariants 26, 27, 28)
	TrustProxyHeaders bool     // default: false
	TrustedProxies    []string // default: empty

	// API Token Extraction (Invariant 22)
	AllowURLToken  bool   // default: false (tokens must not be passed in URL query params)
	APITokenHeader string // default: "Authorization"
	APITokenPrefix string // default: "Bearer "

	// Custom HTML render hooks (nil = use default JSON/HTML fallback)
	CustomWaitRoomHTML  func(r *http.Request, retryAfter time.Duration) string
	CustomChallengeHTML func(r *http.Request, ch *CaptchaChallenge, cfg CaptchaConfig) string
	CustomErrorHTML     func(r *http.Request, err *AdmissionError) string

	// Deterministic Clock Abstraction
	Clock Clock
}

// String redacts sensitive credentials across the entire Config (Invariant 1).
func (c Config) String() string {
	return fmt.Sprintf("Config{StoreConfig:%s, WaitRoom:{Enabled:%t, WaitTime:%v}, Captcha:{Enabled:%t, Length:%d}, RateLimit:{Enabled:%t}, MaxBodyBytes:%d, TrustProxyHeaders:%t}",
		c.StoreConfig.String(), c.WaitRoom.Enabled, c.WaitRoom.WaitTime, c.Captcha.Enabled, c.Captcha.Length, c.RateLimit.Enabled, c.MaxBodyBytes, c.TrustProxyHeaders)
}

// GoString redacts sensitive credentials across the entire Config for %#v (Invariant 1).
func (c Config) GoString() string {
	return c.String()
}

// DefaultConfig returns a production-ready, secure-by-default configuration.
func DefaultConfig() Config {
	return Config{
		Store: nil, // Initialized by Engine if nil
		StoreConfig: StoreConfig{
			Type:             StoreTypeMemory,
			MaxEntries:       10000,
			MaxKeyBytes:      256,
			MaxValueBytes:    65536,
			CleanupInterval:  30 * time.Second,
			RedisPrefix:       "onionguard:",
			RedisFailClosed:   true,
			RedisDialTimeout:  2 * time.Second,
			RedisMaxRetries:   3,
			RedisReadTimeout:  2 * time.Second,
			RedisWriteTimeout: 2 * time.Second,
		},
		WaitRoom: WaitRoomConfig{
			Enabled:  true,
			WaitTime: 5 * time.Second,
		},
		Captcha: CaptchaConfig{
			Enabled:      true,
			Length:       5,
			TTL:          3 * time.Minute,
			MaxAttempts:  3,
			Width:        160,
			Height:       60,
			Alphabet:     "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
			EndpointPath: "/onionguard/challenge",
			Visual: CaptchaVisualConfig{
				NoiseLines:   2,
				NoiseRatio:   0.02,
				JitterPixels: 2,
			},
		},
		RateLimit: RateLimitConfig{
			Enabled: true,
			Limits: map[RateLimitScope]RateLimitRule{
				ScopeAnonymous:     {Rate: 20, Burst: 50, Cost: 1, Window: 1 * time.Minute},
				ScopeAuthenticated: {Rate: 50, Burst: 100, Cost: 1, Window: 1 * time.Minute},
				ScopeAPIToken:      {Rate: 100, Burst: 200, Cost: 1, Window: 1 * time.Minute},
				ScopeChallenge:     {Rate: 5, Burst: 10, Cost: 1, Window: 1 * time.Minute},
				ScopeFirstContact:  {Rate: 100, Burst: 200, Cost: 1, Window: 1 * time.Minute},
			},
		},
		SecurityHeaders: SecurityHeadersConfig{
			Policy:                HeaderPreserve,
			ContentSecurityPolicy: "default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
			XContentTypeOptions:   "nosniff",
			XFrameOptions:         "DENY",
			ReferrerPolicy:        "no-referrer",
		},
		SessionCookieName:       "onionguard_session",
		SessionTTL:              24 * time.Hour,
		CookieSecure:            false, // Plain Tor .onion uses HTTP safely over onion encryption
		CookieHTTPOnly:          true,
		CookieSameSite:          http.SameSiteLaxMode,
		CookiePath:              "/",
		CookieDomain:            "",
		MaxRenewals:             10,
		MaxConcurrentSessions:   10000,
		SessionAbsoluteLifetime: 7 * 24 * time.Hour,
		MaxBodyBytes:            102400, // 100 KiB
		MaxTokenBytes:           4096,
		MaxCookieNameBytes:      64,
		MaxCookieValueBytes:     4096,
		MaxPrincipalIDBytes:     256,
		MaxChallengeIDBytes:     128,
		MaxStoreKeyBytes:        256,
		TrustProxyHeaders:       false, // Invariant 27, 28: Zero trust in client IP headers
		TrustedProxies:          nil,
		AllowURLToken:           false, // Invariant 22: API tokens forbidden in query strings
		APITokenHeader:          "Authorization",
		APITokenPrefix:          "Bearer ",
		Clock:                   RealClock{},
	}
}

// Validate executes strict bounds and integrity checks across the configuration.
func (c *Config) Validate() error {
	if c.Clock == nil {
		c.Clock = RealClock{}
	}

	// Store Validation
	if c.Store == nil {
		if c.StoreConfig.Type == StoreTypeRedis && c.StoreConfig.RedisAddr == "" {
			return errors.New("onionguard: redis address must not be empty")
		}
		if c.StoreConfig.MaxEntries <= 0 {
			return errors.New("onionguard: store max entries must be greater than 0")
		}
		if c.StoreConfig.MaxKeyBytes <= 0 {
			return errors.New("onionguard: store max key bytes must be greater than 0")
		}
		if c.StoreConfig.MaxValueBytes <= 0 {
			return errors.New("onionguard: store max value bytes must be greater than 0")
		}
		if c.StoreConfig.CleanupInterval <= 0 {
			return errors.New("onionguard: store cleanup interval must be positive")
		}
		if c.StoreConfig.RedisPoolSize < 0 {
			return errors.New("onionguard: redis pool size cannot be negative")
		}
		if c.StoreConfig.RedisMinIdleConns < 0 {
			return errors.New("onionguard: redis min idle conns cannot be negative")
		}
		if c.StoreConfig.RedisMaxRetries < 0 {
			return errors.New("onionguard: redis max retries cannot be negative")
		}
		if c.StoreConfig.RedisReadTimeout < 0 {
			return errors.New("onionguard: redis read timeout cannot be negative")
		}
		if c.StoreConfig.RedisWriteTimeout < 0 {
			return errors.New("onionguard: redis write timeout cannot be negative")
		}
		if c.StoreConfig.RedisPoolTimeout < 0 {
			return errors.New("onionguard: redis pool timeout cannot be negative")
		}
	}

	// Wait Room Validation
	if c.WaitRoom.Enabled && c.WaitRoom.WaitTime <= 0 {
		return errors.New("onionguard: wait room wait time must be positive when enabled")
	}

	// CAPTCHA Validation
	if c.Captcha.Enabled {
		if c.Captcha.Width > 800 || c.Captcha.Height > 400 {
			return errors.New("onionguard: captcha dimensions are too large (max 800x400)")
		}
		if c.Captcha.Length < 3 || c.Captcha.Length > 16 {
			return errors.New("onionguard: captcha length must be between 3 and 16")
		}
		if c.Captcha.TTL <= 0 {
			return errors.New("onionguard: captcha TTL must be positive")
		}
		if c.Captcha.MaxAttempts <= 0 {
			return errors.New("onionguard: captcha max attempts must be positive")
		}
		if c.Captcha.Width <= 0 || c.Captcha.Height <= 0 {
			return errors.New("onionguard: captcha dimensions must be positive")
		}
		if len(c.Captcha.Alphabet) < 10 {
			return errors.New("onionguard: captcha alphabet must contain at least 10 characters")
		}
		if c.Captcha.EndpointPath == "" || c.Captcha.EndpointPath[0] != '/' {
			return errors.New("onionguard: challenge endpoint path must start with '/'")
		}
	}

	// Rate Limit Validation
	if c.RateLimit.Enabled {
		if len(c.RateLimit.Limits) == 0 {
			return errors.New("onionguard: rate limiting is enabled but no scope rules configured")
		}
		for scope, rule := range c.RateLimit.Limits {
			if rule.Rate <= 0 {
				return fmt.Errorf("onionguard: rate limit rate for scope %q must be positive", scope)
			}
			if rule.Burst <= 0 {
				return fmt.Errorf("onionguard: rate limit burst for scope %q must be positive", scope)
			}
			if rule.Cost <= 0 {
				return fmt.Errorf("onionguard: rate limit cost for scope %q must be positive", scope)
			}
			if rule.Window <= 0 {
				return fmt.Errorf("onionguard: rate limit window for scope %q must be positive", scope)
			}
		}
	}

	// Session Validation
	if c.SessionCookieName == "" {
		return errors.New("onionguard: session cookie name must not be empty")
	}
	if len(c.SessionCookieName) > c.MaxCookieNameBytes {
		return errors.New("onionguard: session cookie name exceeds configured limit")
	}
	if c.SessionTTL <= 0 {
		return errors.New("onionguard: session TTL must be positive")
	}
	if c.MaxRenewals < 0 {
		return errors.New("onionguard: max renewals cannot be negative")
	}
	if c.MaxConcurrentSessions <= 0 {
		return errors.New("onionguard: max concurrent sessions must be positive")
	}
	if c.SessionAbsoluteLifetime < 0 {
		return errors.New("onionguard: session absolute lifetime cannot be negative")
	}
	if c.MaxTokenBytes <= 0 || c.MaxTokenBytes > 1024*1024 {
		return errors.New("onionguard: max token bytes must be within 1..1048576")
	}
	if c.MaxCookieNameBytes <= 0 || c.MaxCookieNameBytes > 1024 {
		return errors.New("onionguard: max cookie name bytes must be within 1..1024")
	}
	if c.MaxCookieValueBytes <= 0 || c.MaxCookieValueBytes > 1024*1024 {
		return errors.New("onionguard: max cookie value bytes must be within 1..1048576")
	}
	if c.MaxPrincipalIDBytes <= 0 || c.MaxPrincipalIDBytes > 1024*1024 {
		return errors.New("onionguard: max principal ID bytes must be within 1..1048576")
	}
	if c.MaxChallengeIDBytes <= 0 || c.MaxChallengeIDBytes > 1024*1024 {
		return errors.New("onionguard: max challenge ID bytes must be within 1..1048576")
	}
	if c.MaxStoreKeyBytes <= 0 || c.MaxStoreKeyBytes > 1024*1024 {
		return errors.New("onionguard: max store key bytes must be within 1..1048576")
	}

	// Request Limits Validation
	if c.MaxBodyBytes <= 0 {
		return errors.New("onionguard: max body bytes must be positive")
	}
	if c.MaxBodyBytes > 100*1024*1024 { // 100 MiB sanity cap
		return errors.New("onionguard: max body bytes exceeds 100 MiB limit")
	}

	return nil
}
