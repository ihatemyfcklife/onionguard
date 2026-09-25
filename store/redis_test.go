package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRedisStoreIntegration(t *testing.T) {
	addr := os.Getenv("ONIONGUARD_REDIS_ADDR")
	if addr == "" {
		t.Skip("set ONIONGUARD_REDIS_ADDR to run Redis integration tests")
	}
	s, err := NewRedisStore(RedisConfig{Addr: addr, Prefix: "onionguard:test:", DialTimeout: 250 * time.Millisecond})
	if err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	key := "integration"
	_ = s.Delete(ctx, key)
	if err := s.Set(ctx, key, []byte("v"), time.Second); err != nil {
		t.Skipf("redis unavailable: %v", err)
	}
	b, err := s.Get(ctx, key)
	if err != nil || string(b) != "v" {
		t.Fatalf("get: %q %v", b, err)
	}
	if got, err := s.GetDel(ctx, key); err != nil || string(got) != "v" {
		t.Fatalf("getdel: %q %v", got, err)
	}
	if _, err := s.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after getdel: %v", err)
	}
	var wg sync.WaitGroup
	var success int
	var mu sync.Mutex
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.SetNX(ctx, "nx", []byte("1"), time.Second)
			if err != nil {
				return
			}
			if ok {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("expected one SetNX success, got %d", success)
	}
	_ = s.Delete(ctx, "nx")

	if err := s.Set(ctx, "expiry", []byte("v"), 30*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := s.Get(ctx, "expiry"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected expiry, got %v", err)
	}

	const increments = 32
	var incrementWG sync.WaitGroup
	for i := 0; i < increments; i++ {
		incrementWG.Add(1)
		go func() {
			defer incrementWG.Done()
			if _, err := s.IncrementWithTTL(ctx, "counter", 1, time.Second); err != nil {
				t.Errorf("increment: %v", err)
			}
		}()
	}
	incrementWG.Wait()
	got, err := s.Get(ctx, "counter")
	if err != nil || string(got) != "32" {
		t.Fatalf("atomic counter: %q %v", got, err)
	}
	pttl, err := s.client.PTTL(ctx, s.key("counter")).Result()
	if err != nil || pttl <= 0 {
		t.Fatalf("counter TTL missing: %v %v", pttl, err)
	}

	if err := s.Set(ctx, "consume", []byte("one"), time.Second); err != nil {
		t.Fatal(err)
	}
	var consumed int
	var consumeWG sync.WaitGroup
	for i := 0; i < 16; i++ {
		consumeWG.Add(1)
		go func() {
			defer consumeWG.Done()
			if value, err := s.GetDel(ctx, "consume"); err == nil && string(value) == "one" {
				mu.Lock()
				consumed++
				mu.Unlock()
			}
		}()
	}
	consumeWG.Wait()
	if consumed != 1 {
		t.Fatalf("expected one GetDel consumer, got %d", consumed)
	}
}

func TestRedisStore_ClosedPing(t *testing.T) {
	var nilStore *RedisStore
	if err := nilStore.Ping(context.Background()); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed for nil store, got %v", err)
	}
	s, err := NewRedisStore(RedisConfig{Addr: "127.0.0.1:0", DialTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatalf("expected error for closed store, got nil")
	}
}

func TestRedisStore_ConfigurationAndOptions(t *testing.T) {
	// 1. Missing address
	if _, err := NewRedisStore(RedisConfig{Addr: ""}); err == nil {
		t.Fatal("expected error for empty redis address")
	}

	// 2. Invalid URL
	if _, err := NewRedisStore(RedisConfig{Addr: "redis://invalid url with spaces"}); err == nil {
		t.Fatal("expected error for invalid redis URL")
	}

	// 3. Pool and Timeout options configured properly
	cfg := RedisConfig{
		Addr:          "127.0.0.1:6379",
		Prefix:        "testprefix:",
		DialTimeout:   1 * time.Second,
		ReadTimeout:   500 * time.Millisecond,
		WriteTimeout:  500 * time.Millisecond,
		PoolSize:      50,
		MinIdleConns:  10,
		MaxRetries:    5,
		PoolTimeout:   2 * time.Second,
		MaxKeyBytes:   128,
		MaxValueBytes: 1024,
	}
	s, err := NewRedisStore(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating RedisStore: %v", err)
	}
	defer s.Close()

	if s.key("foo") != "testprefix:foo" {
		t.Fatalf("key prefixing mismatch: got %q, want testprefix:foo", s.key("foo"))
	}
}

func TestRedisStore_ClosedMethodsResilience(t *testing.T) {
	s, err := NewRedisStore(RedisConfig{Addr: "127.0.0.1:0", DialTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()

	ctx := context.Background()

	if _, err := s.Get(ctx, "k"); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Get: got %v, want ErrStoreClosed", err)
	}
	if err := s.Set(ctx, "k", []byte("v"), time.Second); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Set: got %v, want ErrStoreClosed", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Delete: got %v, want ErrStoreClosed", err)
	}
	if _, err := s.GetDel(ctx, "k"); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("GetDel: got %v, want ErrStoreClosed", err)
	}
	if _, err := s.SetNX(ctx, "k", []byte("v"), time.Second); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("SetNX: got %v, want ErrStoreClosed", err)
	}
	if _, err := s.IncrementWithTTL(ctx, "k", 1, time.Second); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("IncrementWithTTL: got %v, want ErrStoreClosed", err)
	}
	if _, err := s.CompareAndDelete(ctx, "k", []byte("v")); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("CompareAndDelete: got %v, want ErrStoreClosed", err)
	}
	if _, err := s.CompareAndTouch(ctx, "k", []byte("v"), time.Second); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("CompareAndTouch: got %v, want ErrStoreClosed", err)
	}
	if err := s.Touch(ctx, "k", time.Second); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("Touch: got %v, want ErrStoreClosed", err)
	}
	if _, _, err := s.ConsumeToken(ctx, "k", 1, 1, 1, time.Second, time.Now()); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("ConsumeToken: got %v, want ErrStoreClosed", err)
	}
	if _, err := s.ReserveSession(ctx, "ns", "sess", 10, time.Now().Add(time.Hour)); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("ReserveSession: got %v, want ErrStoreClosed", err)
	}
	if err := s.ReleaseSession(ctx, "ns", "sess"); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("ReleaseSession: got %v, want ErrStoreClosed", err)
	}
	if err := s.MoveSessionReservation(ctx, "ns", "old", "new", time.Now().Add(time.Hour)); !errors.Is(err, ErrStoreClosed) {
		t.Errorf("MoveSessionReservation: got %v, want ErrStoreClosed", err)
	}
}

func TestRedisStore_ValidationBounds(t *testing.T) {
	s, err := NewRedisStore(RedisConfig{
		Addr:          "127.0.0.1:6379",
		MaxKeyBytes:   10,
		MaxValueBytes: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx := context.Background()

	// Empty key
	if _, err := s.Get(ctx, ""); !errors.Is(err, ErrKeyTooLarge) {
		t.Errorf("empty key: got %v, want ErrKeyTooLarge", err)
	}

	// Oversized key
	oversizedKey := "1234567890123" // 13 bytes > 10
	if _, err := s.Get(ctx, oversizedKey); !errors.Is(err, ErrKeyTooLarge) {
		t.Errorf("oversized key: got %v, want ErrKeyTooLarge", err)
	}

	// Oversized value
	oversizedVal := []byte("12345678901234567890123") // 23 bytes > 20
	if err := s.Set(ctx, "k", oversizedVal, time.Second); !errors.Is(err, ErrValueTooLarge) {
		t.Errorf("oversized val: got %v, want ErrValueTooLarge", err)
	}

	// Invalid TTL
	if err := s.Set(ctx, "k", []byte("v"), 0); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("zero TTL: got %v, want ErrInvalidTTL", err)
	}
	if err := s.Set(ctx, "k", []byte("v"), -time.Second); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("negative TTL: got %v, want ErrInvalidTTL", err)
	}
}

func TestRedisStore_ContextCancelled(t *testing.T) {
	s, err := NewRedisStore(RedisConfig{
		Addr: "127.0.0.1:6379",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	if _, err := s.Get(ctx, "k"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on Get, got %v", err)
	}
	if err := s.Set(ctx, "k", []byte("v"), time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on Set, got %v", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled on Delete, got %v", err)
	}
}
