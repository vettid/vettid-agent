package mcp

import (
	"sync"
	"time"
)

// The local rate limit (AGENT-PLAN §4.1): a token bucket of 120, filled
// at 2 a second, per process, in front of every tool call, so that a
// runaway agent is answered rate_limited_local before anything reaches
// the vault.
const (
	DefaultBurst = 120
	DefaultRate  = 2.0 // tokens per second
)

// bucket is a token bucket. It is safe for concurrent use.
type bucket struct {
	mu     sync.Mutex
	now    func() time.Time
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newBucket(rate float64, burst int, now func() time.Time) *bucket {
	return &bucket{now: now, rate: rate, burst: float64(burst), tokens: float64(burst), last: now()}
}

// take takes one token. If none is left it reports how long until one
// is.
func (b *bucket) take() (ok bool, wait time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(b.burst, b.tokens+el*b.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
}
