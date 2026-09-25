package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStoreAtomicsAndTTL(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	ok, err := s.SetNX(ctx, "a", []byte("1"), time.Second)
	if err != nil || !ok {
		t.Fatalf("setnx: %v %v", ok, err)
	}
	ok, err = s.SetNX(ctx, "a", []byte("2"), time.Second)
	if err != nil || ok {
		t.Fatalf("second setnx: %v %v", ok, err)
	}
	b, err := s.GetDel(ctx, "a")
	if err != nil || string(b) != "1" {
		t.Fatalf("getdel: %q %v", b, err)
	}
	if _, err = s.Get(ctx, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestMemoryStore_Ping(t *testing.T) {
	s, err := NewMemoryStore(DefaultMemoryConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("expected ping to succeed, got %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if err := s.Ping(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("expected ErrStoreClosed after close, got %v", err)
	}
}
