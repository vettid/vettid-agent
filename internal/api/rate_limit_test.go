package api

import (
	"testing"
	"time"
)

func TestAPIRateLimiter_BurstThenDeny(t *testing.T) {
	l := newAPIRateLimiter()
	for i := 0; i < apiRateBurst; i++ {
		if !l.Allow() {
			t.Fatalf("Allow returned false within burst at i=%d", i)
		}
	}
	if l.Allow() {
		t.Errorf("Allow returned true after exhausting burst")
	}
}

func TestAPIRateLimiter_Refills(t *testing.T) {
	l := newAPIRateLimiter()
	for i := 0; i < apiRateBurst; i++ {
		l.Allow()
	}
	// Rewind lastRefill so the test doesn't need to sleep.
	l.mu.Lock()
	l.bucket.lastRefill = time.Now().Add(-2 * time.Second)
	l.mu.Unlock()
	if !l.Allow() {
		t.Errorf("Allow returned false after 2s refill window")
	}
}
