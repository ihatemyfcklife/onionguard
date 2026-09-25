package store

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type RedisConfig struct {
	Addr          string
	Password      string
	DB            int
	Prefix        string
	DialTimeout   time.Duration
	FailClosed    bool
	MaxKeyBytes   int
	MaxValueBytes int
	PoolSize      int
	MinIdleConns  int
	MaxRetries    int
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	PoolTimeout   time.Duration
}

var (
	luaGetDel           = redis.NewScript(`local v=redis.call('GET',KEYS[1]); if not v then return false end; redis.call('DEL',KEYS[1]); return v`)
	luaIncrementWithTTL = redis.NewScript(`
local v = redis.call('INCRBY', KEYS[1], ARGV[1])
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return v`)
	luaCompareAndDelete = redis.NewScript(`if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) else return 0 end`)
	luaCompareAndTouch  = redis.NewScript(`if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('PEXPIRE',KEYS[1],ARGV[2]) else return 0 end`)
	luaConsumeToken     = redis.NewScript(`
local raw = redis.call('GET', KEYS[1])
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl = tonumber(ARGV[5])
local tokens
local updated
if raw then
  local sep = string.find(raw, ':', 1, true)
  if sep then
    tokens = tonumber(string.sub(raw, 1, sep-1)) or burst
    updated = tonumber(string.sub(raw, sep+1)) or now
  else
    tokens = burst; updated = now
  end
else
  tokens = burst; updated = now
end
local elapsed = math.max(0, now-updated) / 1000.0
tokens = math.min(burst, tokens + elapsed*rate)
local allowed = 0
local retry_ms = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  retry_ms = math.ceil(((cost-tokens)/rate)*1000)
end
redis.call('SET', KEYS[1], tostring(tokens)..':'..tostring(now), 'PX', ttl)
return {allowed, retry_ms}`)
	luaReserveSession = redis.NewScript(`
local t = redis.call('TIME')
local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now_ms)
if redis.call('ZSCORE', KEYS[1], ARGV[1]) then
  redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
  return 1
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then
  return 0
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
return 1`)
	luaMoveSessionReservation = redis.NewScript(`if redis.call('ZREM',KEYS[1],ARGV[1]) == 0 then return 0 end; redis.call('ZADD',KEYS[1],ARGV[3],ARGV[2]); return 1`)
)

type RedisStore struct {
	client    *redis.Client
	cfg       RedisConfig
	closed    bool
	closeOnce sync.Once
}

func NewRedisStore(cfg RedisConfig) (*RedisStore, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("onionguard: redis address is required")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "onionguard:"
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 2 * time.Second
	}
	if cfg.MaxKeyBytes <= 0 {
		cfg.MaxKeyBytes = 256
	}
	if cfg.MaxValueBytes <= 0 {
		cfg.MaxValueBytes = 65536
	}

	var opt *redis.Options
	if strings.HasPrefix(cfg.Addr, "redis://") || strings.HasPrefix(cfg.Addr, "rediss://") || strings.HasPrefix(cfg.Addr, "unix://") {
		var err error
		opt, err = redis.ParseURL(cfg.Addr)
		if err != nil {
			return nil, fmt.Errorf("onionguard: invalid redis url: %w", err)
		}
	} else {
		opt = &redis.Options{
			Addr:     cfg.Addr,
			Password: cfg.Password,
			DB:       cfg.DB,
		}
	}
	if opt.DialTimeout <= 0 {
		opt.DialTimeout = cfg.DialTimeout
	}
	if cfg.ReadTimeout > 0 {
		opt.ReadTimeout = cfg.ReadTimeout
	} else if opt.ReadTimeout <= 0 {
		opt.ReadTimeout = cfg.DialTimeout
	}
	if cfg.WriteTimeout > 0 {
		opt.WriteTimeout = cfg.WriteTimeout
	} else if opt.WriteTimeout <= 0 {
		opt.WriteTimeout = cfg.DialTimeout
	}
	if cfg.PoolSize > 0 {
		opt.PoolSize = cfg.PoolSize
	}
	if cfg.MinIdleConns > 0 {
		opt.MinIdleConns = cfg.MinIdleConns
	}
	if cfg.MaxRetries >= 0 {
		opt.MaxRetries = cfg.MaxRetries
	}
	if cfg.PoolTimeout > 0 {
		opt.PoolTimeout = cfg.PoolTimeout
	}

	c := redis.NewClient(opt)
	return &RedisStore{client: c, cfg: cfg}, nil
}

func (r *RedisStore) Ping(ctx context.Context) error {
	if r == nil || r.client == nil || r.closed {
		return ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.mapErr(r.client.Ping(ctx).Err())
}

func (r *RedisStore) validateKey(key string) error {
	if len(key) == 0 || len(key) > r.cfg.MaxKeyBytes {
		return ErrKeyTooLarge
	}
	return nil
}
func (r *RedisStore) validate(key string, value []byte) error {
	if err := r.validateKey(key); err != nil {
		return err
	}
	if len(value) > r.cfg.MaxValueBytes {
		return ErrValueTooLarge
	}
	return nil
}

func (r *RedisStore) key(k string) string { return r.cfg.Prefix + k }

func (r *RedisStore) mapErr(err error) error {
	if err == nil {
		return nil
	}
	if err == redis.Nil {
		return ErrNotFound
	}
	return fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
}

func (r *RedisStore) Get(ctx context.Context, key string) ([]byte, error) {
	if r == nil || r.client == nil || r.closed {
		return nil, ErrStoreClosed
	}
	if err := r.validateKey(key); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, err := r.client.Get(ctx, r.key(key)).Bytes()
	return b, r.mapErr(err)
}

func (r *RedisStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if r == nil || r.client == nil || r.closed {
		return ErrStoreClosed
	}
	if err := r.validate(key, value); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrInvalidTTL
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.mapErr(r.client.Set(ctx, r.key(key), value, ttl).Err())
}

func (r *RedisStore) Delete(ctx context.Context, key string) error {
	if r == nil || r.client == nil || r.closed {
		return ErrStoreClosed
	}
	if err := r.validateKey(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.mapErr(r.client.Del(ctx, r.key(key)).Err())
}

func (r *RedisStore) GetDel(ctx context.Context, key string) ([]byte, error) {
	if r == nil || r.client == nil || r.closed {
		return nil, ErrStoreClosed
	}
	if err := r.validateKey(key); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	v, err := luaGetDel.Run(ctx, r.client, []string{r.key(key)}).Result()
	if err != nil {
		return nil, r.mapErr(err)
	}
	if v == nil || v == false {
		return nil, ErrNotFound
	}
	switch x := v.(type) {
	case string:
		return []byte(x), nil
	case []byte:
		return x, nil
	default:
		return nil, ErrInvalidValue
	}
}

func (r *RedisStore) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if r == nil || r.client == nil || r.closed {
		return false, ErrStoreClosed
	}
	if err := r.validate(key, value); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, ErrInvalidTTL
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	ok, err := r.client.SetNX(ctx, r.key(key), value, ttl).Result()
	if err != nil {
		return false, r.mapErr(err)
	}
	return ok, nil
}

func (r *RedisStore) IncrementWithTTL(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	if r == nil || r.client == nil || r.closed {
		return 0, ErrStoreClosed
	}
	if err := r.validateKey(key); err != nil {
		return 0, err
	}
	if ttl <= 0 {
		return 0, ErrInvalidTTL
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ttlMs := ttl.Milliseconds()
	if ttlMs <= 0 {
		ttlMs = 1
	}
	v, err := luaIncrementWithTTL.Run(ctx, r.client, []string{r.key(key)}, delta, ttlMs).Int64()
	if err != nil {
		return 0, r.mapErr(err)
	}
	return v, nil
}

func (r *RedisStore) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if r == nil || r.client == nil || r.closed {
		return false, ErrStoreClosed
	}
	if err := r.validate(key, expected); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	n, err := luaCompareAndDelete.Run(ctx, r.client, []string{r.key(key)}, string(expected)).Int64()
	if err != nil {
		return false, r.mapErr(err)
	}
	return n == 1, nil
}

func (r *RedisStore) CompareAndTouch(ctx context.Context, key string, expected []byte, ttl time.Duration) (bool, error) {
	if r == nil || r.client == nil || r.closed {
		return false, ErrStoreClosed
	}
	if err := r.validate(key, expected); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, ErrInvalidTTL
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	ttlMs := ttl.Milliseconds()
	if ttlMs <= 0 {
		ttlMs = 1
	}
	n, err := luaCompareAndTouch.Run(ctx, r.client, []string{r.key(key)}, string(expected), ttlMs).Int64()
	if err != nil {
		return false, r.mapErr(err)
	}
	return n == 1, nil
}

func (r *RedisStore) Touch(ctx context.Context, key string, ttl time.Duration) error {
	if r == nil || r.client == nil || r.closed {
		return ErrStoreClosed
	}
	if err := r.validateKey(key); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrInvalidTTL
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ok, err := r.client.Expire(ctx, r.key(key), ttl).Result()
	if err != nil {
		return r.mapErr(err)
	}
	if !ok {
		return ErrNotFound
	}
	return nil
}

func (r *RedisStore) ConsumeToken(ctx context.Context, key string, rate float64, burst int, cost int64, ttl time.Duration, now time.Time) (bool, time.Duration, error) {
	if r == nil || r.client == nil || r.closed {
		return false, 0, ErrStoreClosed
	}
	if err := r.validateKey(key); err != nil {
		return false, 0, err
	}
	if rate <= 0 || burst <= 0 || cost <= 0 || ttl <= 0 {
		return false, 0, ErrInvalidValue
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	ttlMs := ttl.Milliseconds()
	if ttlMs <= 0 {
		ttlMs = 1
	}
	vals, err := luaConsumeToken.Run(ctx, r.client, []string{r.key(key)}, now.UnixMilli(), rate, burst, cost, ttlMs).Result()
	if err != nil {
		return false, 0, r.mapErr(err)
	}
	arr, ok := vals.([]interface{})
	if !ok || len(arr) != 2 {
		return false, 0, ErrInvalidValue
	}
	allowed := int64(0)
	retry := int64(0)
	switch x := arr[0].(type) {
	case int64:
		allowed = x
	case int:
		allowed = int64(x)
	case float64:
		allowed = int64(x)
	case string:
		allowed, _ = strconv.ParseInt(x, 10, 64)
	}
	switch x := arr[1].(type) {
	case int64:
		retry = x
	case int:
		retry = int64(x)
	case float64:
		retry = int64(x)
	case string:
		retry, _ = strconv.ParseInt(x, 10, 64)
	}
	if allowed == 1 {
		return true, 0, nil
	}
	if retry < 0 {
		retry = 0
	}
	if retry > math.MaxInt64/int64(time.Millisecond) {
		retry = math.MaxInt64 / int64(time.Millisecond)
	}
	return false, time.Duration(retry) * time.Millisecond, nil
}

func (r *RedisStore) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	var err error
	r.closeOnce.Do(func() {
		r.closed = true
		err = r.client.Close()
	})
	return err
}

func (r *RedisStore) ReserveSession(ctx context.Context, namespace, sessionID string, limit int, expiresAt time.Time) (bool, error) {
	if r == nil || r.client == nil || r.closed {
		return false, ErrStoreClosed
	}
	if namespace == "" || sessionID == "" || limit <= 0 || expiresAt.IsZero() {
		return false, ErrInvalidValue
	}
	// The Lua script uses Redis server TIME for purging stale entries, ensuring
	// wall-clock consistency independent of the caller's clock abstraction.
	n, err := luaReserveSession.Run(ctx, r.client, []string{r.key(namespace)}, sessionID, expiresAt.UnixMilli(), limit).Int64()
	if err != nil {
		return false, r.mapErr(err)
	}
	return n == 1, nil
}
func (r *RedisStore) ReleaseSession(ctx context.Context, namespace, sessionID string) error {
	if r == nil || r.client == nil || r.closed {
		return ErrStoreClosed
	}
	return r.mapErr(r.client.ZRem(ctx, r.key(namespace), sessionID).Err())
}
func (r *RedisStore) MoveSessionReservation(ctx context.Context, namespace, oldID, newID string, expiresAt time.Time) error {
	if r == nil || r.client == nil || r.closed {
		return ErrStoreClosed
	}
	n, err := luaMoveSessionReservation.Run(ctx, r.client, []string{r.key(namespace)}, oldID, newID, expiresAt.UnixMilli()).Int64()
	if err != nil {
		return r.mapErr(err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
