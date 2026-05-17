package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SECURITY (#110): token-bucket rate limit on the local REST + WS
// endpoints.
//
// Why: the agent runs as a sidecar to an AI client. A misbehaving
// client (or a malicious tool acting as one) can otherwise drive a
// tight loop into the secret-request / send-message endpoints — every
// invocation rides through NATS to the vault and back, so the cost
// per call is non-trivial. The vault-side per-connection rate-limit
// (#32 in vault-manager) also catches this, but a local guard fails
// fast without burning a NATS round-trip.
//
// Bucket parameters: 120-msg burst, 2 msg/sec sustained. Tuned for a
// human-driven AI workflow (typical: < 1 msg/sec, occasional bursts
// for catalog enumeration or batch operations) while bounding the
// long-run rate.

const (
	apiRateBurst        = 120
	apiRateTokensPerSec = 2.0
)

type apiTokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

type apiRateLimiter struct {
	mu      sync.Mutex
	bucket  apiTokenBucket
	burst   float64
	refill  float64
}

func newAPIRateLimiter() *apiRateLimiter {
	return &apiRateLimiter{
		bucket: apiTokenBucket{
			tokens:     apiRateBurst,
			lastRefill: time.Now(),
		},
		burst:  apiRateBurst,
		refill: apiRateTokensPerSec,
	}
}

// Allow debits one token. Returns false when the bucket is empty.
// Single-bucket: the local API is single-tenant by design (one AI
// client per agent instance), so per-source attribution would be
// security theatre — the caller already controls the entire local
// process.
func (l *apiRateLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.bucket.lastRefill).Seconds()
	if elapsed > 0 {
		l.bucket.tokens += elapsed * l.refill
		if l.bucket.tokens > l.burst {
			l.bucket.tokens = l.burst
		}
		l.bucket.lastRefill = now
	}
	if l.bucket.tokens < 1 {
		return false
	}
	l.bucket.tokens -= 1
	return true
}

// rateLimitMiddleware refuses requests with 429 Too Many Requests
// when the bucket is empty.
func rateLimitMiddleware(next http.Handler, limiter *apiRateLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			log.Warn().Str("path", r.URL.Path).Msg("API rate-limited — dropping")
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
