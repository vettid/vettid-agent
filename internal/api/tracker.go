package api

import (
	"encoding/json"
	"sync"
	"time"
)

// RequestStatus represents the state of a tracked request.
type RequestStatus string

const (
	StatusPending         RequestStatus = "pending"
	StatusPendingApproval RequestStatus = "pending_approval"
	StatusApproved        RequestStatus = "approved"
	StatusCompleted       RequestStatus = "completed"
	StatusDenied          RequestStatus = "denied"
	StatusTimeout         RequestStatus = "timeout"
	StatusError           RequestStatus = "error"
)

// TrackedResult is the outcome of a secret or action request.
//
// SECURITY (#67 + #108): SecretValue is `string` because the JSON
// wire format requires it — both the vault-side and the AI client
// consume it as text. String immutability in Go means we cannot
// scrub the underlying byte storage from this side; the
// `result.SecretValue = ""` calls in the handlers drop the only
// application-side reference so GC can reclaim it, but the value
// is still on the heap until the next collection cycle, and
// json.Unmarshal at the inbound boundary leaves its own copy.
//
// Lifecycle defences in place:
//   - Decrypt path uses ZeroBytes(plaintext) on the AEAD output —
//     that scrubs the byte buffer json.Unmarshal copied from.
//   - Tracker hands ownership to the HTTP/WS handler, which clears
//     SecretValue immediately after writing the response.
//   - Tracker.Resolve only delivers each result once; subsequent
//     reads return nil (see tracker_test.go).
//
// To meaningfully strengthen this we'd need a wire-format change
// to []byte-typed secret values plus a SecureBytes wrapper threaded
// through every consumer — a future refactor.
type TrackedResult struct {
	Status      RequestStatus   `json:"status"`
	RequestID   string          `json:"request_id"`
	SecretValue string          `json:"secret_value,omitempty"` // retrieve mode only
	ExpiresAt   string          `json:"expires_at,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"` // use mode only
	Reason      string          `json:"reason,omitempty"`
}

type trackedEntry struct {
	ch        chan *TrackedResult
	result    *TrackedResult
	expiresAt time.Time
}

// RequestTracker correlates outgoing requests with async NATS responses.
type RequestTracker struct {
	mu             sync.Mutex
	entries        map[string]*trackedEntry
	defaultTimeout time.Duration
	done           chan struct{}
}

// NewRequestTracker creates a tracker with the given default timeout.
// Call Stop() to release the background reaper goroutine.
func NewRequestTracker(defaultTimeout time.Duration) *RequestTracker {
	rt := &RequestTracker{
		entries:        make(map[string]*trackedEntry),
		defaultTimeout: defaultTimeout,
		done:           make(chan struct{}),
	}
	go rt.reaper()
	return rt
}

// Add registers a new request and returns a channel that will receive the result.
// The channel is buffered(1) so the sender never blocks.
func (rt *RequestTracker) Add(requestID string, timeout time.Duration) chan *TrackedResult {
	if timeout == 0 {
		timeout = rt.defaultTimeout
	}

	ch := make(chan *TrackedResult, 1)

	rt.mu.Lock()
	rt.entries[requestID] = &trackedEntry{
		ch:        ch,
		expiresAt: time.Now().Add(timeout),
	}
	rt.mu.Unlock()

	return ch
}

// Resolve delivers a result for a tracked request.
// Returns true if the request was found and resolved.
// For pending_approval: resolves the current wait, keeps the entry with a new
// channel for the final response.
func (rt *RequestTracker) Resolve(requestID string, result *TrackedResult) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	entry, ok := rt.entries[requestID]
	if !ok {
		return false
	}

	if result.Status == StatusPendingApproval {
		// Send the pending_approval to the current waiter
		select {
		case entry.ch <- result:
		default:
		}
		// Create a new channel for the final response
		entry.ch = make(chan *TrackedResult, 1)
		entry.result = result
		return true
	}

	// Final resolution — send and store result
	select {
	case entry.ch <- result:
	default:
	}
	entry.result = result
	return true
}

// Get returns the current result for a request, or nil if not found.
func (rt *RequestTracker) Get(requestID string) *TrackedResult {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	entry, ok := rt.entries[requestID]
	if !ok {
		return nil
	}
	return entry.result
}

// Stop shuts down the background reaper goroutine.
func (rt *RequestTracker) Stop() {
	close(rt.done)
}

// reaper periodically cleans up timed-out entries.
func (rt *RequestTracker) reaper() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rt.done:
			return
		case now := <-ticker.C:
			rt.mu.Lock()
			for id, entry := range rt.entries {
				if now.After(entry.expiresAt) {
					// Only timeout if not already resolved
					if entry.result == nil || entry.result.Status == StatusPendingApproval {
						timeoutResult := &TrackedResult{
							Status:    StatusTimeout,
							RequestID: id,
							Reason:    "request timed out",
						}
						select {
						case entry.ch <- timeoutResult:
						default:
						}
						entry.result = timeoutResult
					}
					// Remove entries that are past expiry + 5 minutes (keep for polling)
					if now.After(entry.expiresAt.Add(5 * time.Minute)) {
						delete(rt.entries, id)
					}
				}
			}
			rt.mu.Unlock()
		}
	}
}
