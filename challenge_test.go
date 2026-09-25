package onionguard

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"onionguard/store"
)

func TestChallenge_IssueReuseValidate(t *testing.T) {
	s, err := store.NewMemoryStore(store.DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	clock := NewTestClock(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true
	sess, _ := NewSession(clock.Now(), 3)
	sess.State = StateChallengeRequired
	sess.ExpiresAt = clock.Now().Add(time.Hour)
	if err := SaveSession(context.Background(), s, sess, time.Hour); err != nil {
		t.Fatal(err)
	}
	cs := NewChallengeService(cfg, s, clock)
	ch, err := cs.Issue(context.Background(), sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	ch2, err := cs.Issue(context.Background(), sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if ch.ID != ch2.ID {
		t.Fatalf("expected challenge reuse, got %s and %s", ch.ID, ch2.ID)
	}
	data, err := s.Get(context.Background(), challengeKey(ch.ID))
	if err != nil {
		t.Fatal(err)
	}
	var stored storedChallenge
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	// Deterministic success without exposing the real answer to production code.
	stored.AnswerHash = sha256Bytes("ABCDE")
	mutated, _ := json.Marshal(stored)
	if err := s.Set(context.Background(), challengeKey(ch.ID), mutated, stored.ExpiresAt.Sub(clock.Now())); err != nil {
		t.Fatal(err)
	}
	if err := cs.Validate(context.Background(), sess.SessionID, "ABCDE"); err != nil {
		t.Fatal(err)
	}
	loaded, err := GetSession(context.Background(), s, sess.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.State != StateAdmitted || loaded.ChallengeID != "" {
		t.Fatalf("unexpected admitted state: %+v", loaded)
	}
	if err := cs.Validate(context.Background(), sess.SessionID, "ABCDE"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected replay to fail, got %v", err)
	}
}

func TestChallenge_MaxAttempts(t *testing.T) {
	s, _ := store.NewMemoryStore(store.DefaultMemoryConfig())
	defer s.Close()
	clock := NewTestClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	cfg := DefaultConfig()
	cfg.WaitRoom.Enabled = false
	cfg.Captcha.Enabled = true
	cfg.Captcha.MaxAttempts = 2
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
	stored.AnswerHash = sha256Bytes("AAAAA")
	mutated, _ := json.Marshal(stored)
	_ = s.Set(context.Background(), challengeKey(ch.ID), mutated, stored.ExpiresAt.Sub(clock.Now()))
	if err := cs.Validate(context.Background(), ss.SessionID, "BBBBB"); !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("first wrong answer: %v", err)
	}
	if err := cs.Validate(context.Background(), ss.SessionID, "BBBBB"); !errors.Is(err, ErrMaxAttemptsExceeded) {
		t.Fatalf("second wrong answer: %v", err)
	}
}
