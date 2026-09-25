package onionguard

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"onionguard/store"
)

func TestRace_MemoryStoreTokenBucket(t *testing.T) {
	s, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer s.Close()
	clock := RealClock{}
	cfg := DefaultConfig()
	cfg.RateLimit.Limits[ScopeAnonymous] = RateLimitRule{Rate: 1000, Burst: 1000, Cost: 1, Window: time.Minute}
	rl := NewRateLimiter(cfg, s, clock)
	id := ClientIdentity{Kind: IdentityAnonymous, SessionID: "race-session"}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = rl.Allow(context.Background(), id, "GET:/race", 0) }()
	}
	wg.Wait()
}

func TestRace_ConcurrentChallengeValidation(t *testing.T) {
	s, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer s.Close()
	clock := NewTestClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true
	cfg.RateLimit.Enabled = false
	ss, _ := NewSession(clock.Now(), 3)
	ss.State = StateChallengeRequired
	ss.ExpiresAt = clock.Now().Add(time.Hour)
	_ = SaveSession(context.Background(), s, ss, time.Hour)
	cs := NewChallengeService(cfg, s, clock)
	ch, err := cs.Issue(context.Background(), ss.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := s.Get(context.Background(), challengeKey(ch.ID))
	var stored storedChallenge
	_ = json.Unmarshal(data, &stored)
	stored.AnswerHash = sha256Bytes("ABCDE")
	mutated, _ := json.Marshal(stored)
	_ = s.Set(context.Background(), challengeKey(ch.ID), mutated, stored.ExpiresAt.Sub(clock.Now()))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = cs.Validate(context.Background(), ss.SessionID, "ABCDE") }()
	}
	wg.Wait()
	loaded, err := GetSession(context.Background(), s, ss.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != StateAdmitted {
		t.Fatalf("expected admitted, got %s", loaded.State)
	}
}
