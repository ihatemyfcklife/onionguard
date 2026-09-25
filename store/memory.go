package store

import (
	"context"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

type MemoryConfig struct {
	MaxEntries      int
	MaxKeyBytes     int
	MaxValueBytes   int
	CleanupInterval time.Duration
	Clock           Clock
}

func DefaultMemoryConfig() MemoryConfig {
	return MemoryConfig{MaxEntries: 10000, MaxKeyBytes: 256, MaxValueBytes: 65536, CleanupInterval: 30 * time.Second}
}

type memoryEntry struct {
	value     []byte
	expiresAt time.Time
}

type memoryBucket struct {
	tokens    float64
	updatedAt time.Time
	expiresAt time.Time
}

type MemoryStore struct {
	mu           sync.RWMutex
	entries      map[string]memoryEntry
	buckets      map[string]memoryBucket
	reservations map[string]time.Time
	counts       map[string]int
	cfg          MemoryConfig
	clock        Clock
	closed       bool
	stop         chan struct{}
	done         chan struct{}
	closeOnce    sync.Once
}

func NewMemoryStore(cfg MemoryConfig) (*MemoryStore, error) {
	if cfg.MaxEntries <= 0 || cfg.MaxKeyBytes <= 0 || cfg.MaxValueBytes <= 0 || cfg.CleanupInterval <= 0 {
		return nil, ErrInvalidValue
	}
	s := &MemoryStore{
		entries:      make(map[string]memoryEntry),
		buckets:      make(map[string]memoryBucket),
		reservations: make(map[string]time.Time),
		counts:       make(map[string]int),
		cfg:          cfg,
		clock:        cfg.Clock,
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	go s.janitor()
	return s, nil
}

func (s *MemoryStore) SetClock(c Clock) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = c
}

func (s *MemoryStore) nowLocked() time.Time {
	if s.clock != nil {
		return s.clock.Now()
	}
	return time.Now()
}

func (s *MemoryStore) Ping(ctx context.Context) error {
	if s == nil {
		return ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrStoreClosed
	}
	return nil
}

func reservationKey(namespace, sessionID string) string { return namespace + "\x00" + sessionID }
func (s *MemoryStore) purgeReservationsLocked(now time.Time) {
	for k, expiry := range s.reservations {
		if !now.Before(expiry) {
			delete(s.reservations, k)
			if idx := strings.IndexByte(k, 0); idx != -1 {
				ns := k[:idx]
				if s.counts[ns] > 0 {
					s.counts[ns]--
				}
			}
		}
	}
}

func (s *MemoryStore) countReservationsInNamespaceLocked(namespace string, now time.Time) int {
	prefix := namespace + "\x00"
	count := 0
	for k, expiry := range s.reservations {
		if strings.HasPrefix(k, prefix) {
			if !now.Before(expiry) {
				delete(s.reservations, k)
			} else {
				count++
			}
		}
	}
	s.counts[namespace] = count
	return count
}

func (s *MemoryStore) ReserveSession(ctx context.Context, namespace, sessionID string, limit int, expiresAt time.Time) (bool, error) {
	if s == nil {
		return false, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if namespace == "" || sessionID == "" || limit <= 0 || expiresAt.IsZero() {
		return false, ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrStoreClosed
	}
	k := reservationKey(namespace, sessionID)
	now := s.nowLocked()
	if _, exists := s.reservations[k]; !exists {
		if s.counts[namespace] >= limit {
			if s.countReservationsInNamespaceLocked(namespace, now) >= limit {
				return false, nil
			}
		}
		s.counts[namespace]++
	}
	s.reservations[k] = expiresAt
	return true, nil
}
func (s *MemoryStore) ReleaseSession(ctx context.Context, namespace, sessionID string) error {
	if s == nil {
		return ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	k := reservationKey(namespace, sessionID)
	if _, exists := s.reservations[k]; exists {
		delete(s.reservations, k)
		if s.counts[namespace] > 0 {
			s.counts[namespace]--
		}
	}
	return nil
}
func (s *MemoryStore) MoveSessionReservation(ctx context.Context, namespace, oldID, newID string, expiresAt time.Time) error {
	if s == nil {
		return ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	old := reservationKey(namespace, oldID)
	if _, ok := s.reservations[old]; !ok {
		return ErrNotFound
	}
	delete(s.reservations, old)
	s.reservations[reservationKey(namespace, newID)] = expiresAt
	return nil
}

func (s *MemoryStore) validate(key string, value []byte) error {
	if len(key) == 0 || len(key) > s.cfg.MaxKeyBytes {
		return ErrKeyTooLarge
	}
	if len(value) > s.cfg.MaxValueBytes {
		return ErrValueTooLarge
	}
	return nil
}

func (s *MemoryStore) isClosedLocked() bool { return s.closed }

func (s *MemoryStore) evictOldestEntryLocked() {
	var oldestKey string
	var oldestExp time.Time
	for k, ent := range s.entries {
		if oldestKey == "" || ent.expiresAt.Before(oldestExp) {
			oldestKey = k
			oldestExp = ent.expiresAt
		}
	}
	if oldestKey != "" {
		delete(s.entries, oldestKey)
	}
}

func (s *MemoryStore) evictOldestBucketLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, bkt := range s.buckets {
		if oldestKey == "" || bkt.updatedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = bkt.updatedAt
		}
	}
	if oldestKey != "" {
		delete(s.buckets, oldestKey)
	}
}

func (s *MemoryStore) Get(ctx context.Context, key string) ([]byte, error) {
	if s == nil {
		return nil, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, ErrStoreClosed
	}
	ent, ok := s.entries[key]
	if !ok {
		s.mu.RUnlock()
		return nil, ErrNotFound
	}
	now := s.nowLocked()
	if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
		s.mu.RUnlock()
		s.mu.Lock()
		if !s.closed {
			if e, exists := s.entries[key]; exists && !e.expiresAt.IsZero() && !s.nowLocked().Before(e.expiresAt) {
				delete(s.entries, key)
			}
		}
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	val := append([]byte(nil), ent.value...)
	s.mu.RUnlock()
	return val, nil
}

func (s *MemoryStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if s == nil {
		return ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrInvalidTTL
	}
	if err := s.validate(key, value); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	now := s.nowLocked()
	if _, exists := s.entries[key]; !exists && len(s.entries) >= s.cfg.MaxEntries {
		s.expireLocked(now)
		if len(s.entries) >= s.cfg.MaxEntries {
			s.evictOldestEntryLocked()
		}
	}
	s.entries[key] = memoryEntry{value: append([]byte(nil), value...), expiresAt: now.Add(ttl)}
	return nil
}

func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	if s == nil {
		return ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	delete(s.entries, key)
	return nil
}

func (s *MemoryStore) GetDel(ctx context.Context, key string) ([]byte, error) {
	if s == nil {
		return nil, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	ent, ok := s.entries[key]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.entries, key)
	now := s.nowLocked()
	if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
		return nil, ErrNotFound
	}
	return append([]byte(nil), ent.value...), nil
}

func (s *MemoryStore) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if s == nil {
		return false, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, ErrInvalidTTL
	}
	if err := s.validate(key, value); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrStoreClosed
	}
	now := s.nowLocked()
	if ent, exists := s.entries[key]; exists {
		if ent.expiresAt.IsZero() || now.Before(ent.expiresAt) {
			return false, nil
		}
		delete(s.entries, key)
	}
	if len(s.entries) >= s.cfg.MaxEntries {
		s.expireLocked(now)
		if len(s.entries) >= s.cfg.MaxEntries {
			s.evictOldestEntryLocked()
		}
	}
	s.entries[key] = memoryEntry{value: append([]byte(nil), value...), expiresAt: now.Add(ttl)}
	return true, nil
}

func (s *MemoryStore) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if s == nil {
		return false, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrStoreClosed
	}
	ent, ok := s.entries[key]
	if !ok {
		return false, nil
	}
	now := s.nowLocked()
	if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
		delete(s.entries, key)
		return false, nil
	}
	if string(ent.value) != string(expected) {
		return false, nil
	}
	delete(s.entries, key)
	return true, nil
}

func (s *MemoryStore) CompareAndTouch(ctx context.Context, key string, expected []byte, ttl time.Duration) (bool, error) {
	if s == nil {
		return false, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, ErrInvalidTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrStoreClosed
	}
	ent, ok := s.entries[key]
	now := s.nowLocked()
	if !ok || (!ent.expiresAt.IsZero() && !now.Before(ent.expiresAt)) || string(ent.value) != string(expected) {
		return false, nil
	}
	ent.expiresAt = now.Add(ttl)
	s.entries[key] = ent
	return true, nil
}

func (s *MemoryStore) Touch(ctx context.Context, key string, ttl time.Duration) error {
	if s == nil {
		return ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrInvalidTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	ent, ok := s.entries[key]
	if !ok {
		return ErrNotFound
	}
	now := s.nowLocked()
	if !ent.expiresAt.IsZero() && !now.Before(ent.expiresAt) {
		delete(s.entries, key)
		return ErrNotFound
	}
	ent.expiresAt = now.Add(ttl)
	s.entries[key] = ent
	return nil
}

func (s *MemoryStore) IncrementWithTTL(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	if s == nil {
		return 0, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if ttl <= 0 {
		return 0, ErrInvalidTTL
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrStoreClosed
	}
	now := s.nowLocked()
	ent, ok := s.entries[key]
	var current int64
	if ok && (ent.expiresAt.IsZero() || now.Before(ent.expiresAt)) {
		parsed, err := s.parseCounter(ent.value)
		if err != nil {
			return 0, ErrInvalidValue
		}
		current = parsed
	} else if ok {
		delete(s.entries, key)
	}
	next := current + delta
	if next < 0 {
		return 0, ErrInvalidValue
	}
	value := formatCounter(next)
	if err := s.validate(key, value); err != nil {
		return 0, err
	}
	if !ok && len(s.entries) >= s.cfg.MaxEntries {
		s.expireLocked(now)
		if len(s.entries) >= s.cfg.MaxEntries {
			s.evictOldestEntryLocked()
		}
	}
	s.entries[key] = memoryEntry{value: value, expiresAt: now.Add(ttl)}
	return next, nil
}

func (s *MemoryStore) parseCounter(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, ErrInvalidValue
	}
	return strconv.ParseInt(string(b), 10, 64)
}

func formatCounter(v int64) []byte {
	return []byte(strconv.FormatInt(v, 10))
}

func (s *MemoryStore) ConsumeToken(ctx context.Context, key string, rate float64, burst int, cost int64, ttl time.Duration, now time.Time) (bool, time.Duration, error) {
	if s == nil {
		return false, 0, ErrStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return false, 0, err
	}
	if rate <= 0 || burst <= 0 || cost <= 0 || ttl <= 0 {
		return false, 0, ErrInvalidValue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, 0, ErrStoreClosed
	}
	b, ok := s.buckets[key]
	if !ok && len(s.buckets) >= s.cfg.MaxEntries {
		s.expireLocked(now)
		if len(s.buckets) >= s.cfg.MaxEntries {
			s.evictOldestBucketLocked()
		}
	}
	if !ok || !b.expiresAt.IsZero() && !now.Before(b.expiresAt) {
		b = memoryBucket{tokens: float64(burst), updatedAt: now, expiresAt: now.Add(ttl)}
	} else {
		elapsed := now.Sub(b.updatedAt).Seconds()
		if elapsed > 0 {
			b.tokens = math.Min(float64(burst), b.tokens+elapsed*rate)
			b.updatedAt = now
		}
		b.expiresAt = now.Add(ttl)
	}
	if b.tokens >= float64(cost) {
		b.tokens -= float64(cost)
		s.buckets[key] = b
		return true, 0, nil
	}
	missing := float64(cost) - b.tokens
	waitSec := math.Ceil(missing / rate)
	if waitSec < 0 {
		waitSec = 0
	}
	maxSec := float64(math.MaxInt64 / int64(time.Second))
	if waitSec > maxSec {
		waitSec = maxSec
	}
	wait := time.Duration(waitSec) * time.Second
	s.buckets[key] = b
	return false, wait, nil
}

func (s *MemoryStore) expireLocked(now time.Time) {
	for k, e := range s.entries {
		if !e.expiresAt.IsZero() && !now.Before(e.expiresAt) {
			delete(s.entries, k)
		}
	}
	for k, b := range s.buckets {
		if !b.expiresAt.IsZero() && !now.Before(b.expiresAt) {
			delete(s.buckets, k)
		}
	}
}

func (s *MemoryStore) janitor() {
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()
	defer close(s.done)
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			now := s.nowLocked()
			s.expireLocked(now)
			s.purgeReservationsLocked(now)
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}

func (s *MemoryStore) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() { s.mu.Lock(); s.closed = true; s.mu.Unlock(); close(s.stop); <-s.done })
	return nil
}
