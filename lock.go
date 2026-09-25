package onionguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"time"

	"onionguard/store"
)

const admissionLockTTL = 10 * time.Second

func lockOwnerToken() ([]byte, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	out := make([]byte, hex.EncodedLen(len(b)))
	hex.Encode(out, b)
	return out, nil
}

func acquireLock(ctx context.Context, s store.Store, key string, ttl time.Duration) ([]byte, error) {
	if s == nil {
		return nil, store.ErrStoreClosed
	}
	owner, err := lockOwnerToken()
	if err != nil {
		return nil, err
	}
	// A request burst can legitimately serialize many short session transitions.
	// Keep the wait bounded, but long enough for the documented concurrent
	// admission path instead of failing closed merely because of local contention.
	deadline := time.Now().Add(2 * time.Second)
	for attempt := 0; time.Now().Before(deadline); attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ok, err := s.SetNX(ctx, key, owner, ttl)
		if err != nil {
			return nil, err
		}
		if ok {
			return owner, nil
		}
		delay := calculateBackoffDelay(attempt)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, store.ErrLockUnavailable
}

func calculateBackoffDelay(attempt int) time.Duration {
	const (
		baseDelay = 4 * time.Millisecond
		capDelay  = 50 * time.Millisecond
		minDelay  = 1 * time.Millisecond
	)
	shift := attempt
	if shift > 6 {
		shift = 6
	}
	temp := baseDelay * (1 << shift)
	if temp > capDelay {
		temp = capDelay
	}
	limit := int64(temp - minDelay)
	if limit <= 0 {
		return minDelay
	}
	n, err := rand.Int(rand.Reader, big.NewInt(limit+1))
	if err != nil {
		return minDelay + time.Duration(attempt%10)*time.Millisecond
	}
	return minDelay + time.Duration(n.Int64())
}

func releaseLock(ctx context.Context, s store.Store, key string, owner []byte) error {
	cd, ok := s.(store.ConditionalDeleter)
	if !ok {
		return store.ErrLockUnavailable
	}
	_, err := cd.CompareAndDelete(ctx, key, owner)
	return err
}

func withSessionLock(ctx context.Context, s store.Store, sessionID string, fn func() error) error {
	owner, err := acquireLock(ctx, s, "lock:"+SessionKey(sessionID), admissionLockTTL)
	if err != nil {
		return err
	}
	key := "lock:" + SessionKey(sessionID)
	stop := make(chan struct{})
	done := make(chan struct{})
	if toucher, ok := s.(store.ConditionalToucher); ok {
		go func() {
			defer close(done)
			ticker := time.NewTicker(admissionLockTTL / 3)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					touchCtx, touchCancel := context.WithTimeout(context.Background(), 2*time.Second)
					ok, touchErr := toucher.CompareAndTouch(touchCtx, key, owner, admissionLockTTL)
					touchCancel()
					if touchErr != nil || !ok {
						return
					}
				}
			}
		}()
	} else {
		close(done)
	}
	defer func() {
		close(stop)
		<-done
		relCtx, relCancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = releaseLock(relCtx, s, key, owner)
		relCancel()
	}()
	return fn()
}
