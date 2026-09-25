package onionguard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"onionguard/store"
)

type RateLimitResult struct {
	Allowed    bool
	RetryAfter time.Duration
	Scope      RateLimitScope
}

type RateLimiter struct {
	cfg   Config
	store store.Store
	clock Clock
}

func NewRateLimiter(cfg Config, s store.Store, clock Clock) *RateLimiter {
	if clock == nil {
		clock = RealClock{}
	}
	return &RateLimiter{cfg: cfg, store: s, clock: clock}
}

func hashOperation(op string) string {
	if len(op) > 256 {
		op = op[:256]
	}
	h := sha256.Sum256([]byte(op))
	return hex.EncodeToString(h[:8])
}

func (rl *RateLimiter) Allow(ctx context.Context, id ClientIdentity, operation string, overrideCost int64) (RateLimitResult, error) {
	if rl == nil || !rl.cfg.RateLimit.Enabled {
		return RateLimitResult{Allowed: true, Scope: id.RateLimitScope()}, nil
	}
	scope := id.RateLimitScope()
	if strings.HasPrefix(operation, "challenge:") {
		scope = ScopeChallenge
	} else if scope == ScopeAnonymous && id.SessionID == "" {
		if _, exists := rl.cfg.RateLimit.Limits[ScopeFirstContact]; exists {
			scope = ScopeFirstContact
		}
	}
	rule, ok := rl.cfg.RateLimit.Limits[scope]
	if !ok {
		return RateLimitResult{Allowed: true, Scope: scope}, nil
	}
	cost := rule.Cost
	if overrideCost > 0 {
		cost = overrideCost
	}
	key := "rl:" + string(scope) + ":" + id.RateLimitKey()
	if strings.HasPrefix(operation, "challenge:") {
		key += ":op:" + hashOperation(operation)
	}
	if rl.store == nil {
		if !rl.cfg.StoreConfig.RedisFailClosed {
			return RateLimitResult{Allowed: true, Scope: scope}, nil
		}
		return RateLimitResult{Allowed: false, Scope: scope}, store.ErrStoreClosed
	}
	now := time.Now()
	if rl.clock != nil {
		now = rl.clock.Now()
	}
	if tb, ok := rl.store.(store.TokenBucketStore); ok {
		allowed, retry, err := tb.ConsumeToken(ctx, key, rule.Rate, rule.Burst, cost, rule.Window, now)
		if err != nil {
			if !rl.cfg.StoreConfig.RedisFailClosed && errors.Is(err, store.ErrStoreUnavailable) {
				return RateLimitResult{Allowed: true, Scope: scope}, nil
			}
			return RateLimitResult{Allowed: false, Scope: scope}, err
		}
		if !allowed {
			return RateLimitResult{Allowed: false, RetryAfter: retry, Scope: scope}, ErrRateLimited
		}
		return RateLimitResult{Allowed: true, Scope: scope}, nil
	}
	// Conservative compatibility fallback: fixed counter window. Our built-in stores implement
	// TokenBucketStore; custom stores receive a bounded and TTL-backed approximation.
	v, err := rl.store.IncrementWithTTL(ctx, key, cost, rule.Window)
	if err != nil {
		if !rl.cfg.StoreConfig.RedisFailClosed && errors.Is(err, store.ErrStoreUnavailable) {
			return RateLimitResult{Allowed: true, Scope: scope}, nil
		}
		return RateLimitResult{Allowed: false, Scope: scope}, err
	}
	if v > int64(rule.Burst) {
		return RateLimitResult{Allowed: false, RetryAfter: rule.Window, Scope: scope}, ErrRateLimited
	}
	return RateLimitResult{Allowed: true, Scope: scope}, nil
}
