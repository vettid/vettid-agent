package api

import (
	"sort"
	"sync"
	"time"
)

// LoggedMessage is one entry in the bidirectional message log: either
// an inbound owner→agent message (direction="incoming") or an
// outbound agent→owner message (direction="outgoing"). The AI process
// polls GET /v1/messages to recover recent conversation context after
// it (re)starts.
type LoggedMessage struct {
	MessageID string    `json:"message_id"`
	Direction string    `json:"direction"` // "incoming" or "outgoing"
	Content   string    `json:"content,omitempty"`
	ReplyTo   string    `json:"reply_to,omitempty"`
	Action    string    `json:"action,omitempty"`
	SentAt    time.Time `json:"sent_at"`
}

// MessageLog is a thread-safe bounded ring of recent
// owner↔agent messages. Distinct from MessageInbox (which is a
// one-shot pickup buffer drained on read) — this log keeps every
// message regardless of consumer state until eviction, so an AI
// process can backfill context on restart.
//
// Bounded so a long-running daemon with a chatty owner can't leak
// memory. messageLogCapDefault is sized generously enough that a
// typical conversation session fits without eviction; older messages
// drop off the back when the cap is reached.
type MessageLog struct {
	mu       sync.RWMutex
	messages []LoggedMessage
	cap      int
}

const messageLogCapDefault = 1000

func NewMessageLog() *MessageLog {
	return &MessageLog{cap: messageLogCapDefault}
}

// Append adds a message to the log, evicting the oldest if the buffer
// is at capacity. Messages are stored in insertion order, which the
// caller is responsible for keeping aligned with SentAt (we don't
// re-sort on each append — too expensive for a hot path).
func (l *MessageLog) Append(msg LoggedMessage) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.messages) >= l.cap {
		l.messages = l.messages[1:]
	}
	l.messages = append(l.messages, msg)
}

// Recent returns up to `limit` messages strictly older than the
// message identified by `before` (when non-empty), oldest-first.
// Empty `before` returns the newest `limit` messages.
//
// The returned slice is a fresh copy; the caller owns it. limit==0
// uses a default of 50; values >200 are clamped.
func (l *MessageLog) Recent(limit int, before string) []LoggedMessage {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	// Find the cursor index. If `before` is empty or not found, the
	// cursor is past the end of the slice (full window available).
	cursor := len(l.messages)
	if before != "" {
		for i, m := range l.messages {
			if m.MessageID == before {
				cursor = i
				break
			}
		}
	}

	// Window: [start, cursor) — the `limit` newest messages strictly
	// older than the cursor.
	start := cursor - limit
	if start < 0 {
		start = 0
	}
	if start >= cursor {
		return []LoggedMessage{}
	}

	out := make([]LoggedMessage, cursor-start)
	copy(out, l.messages[start:cursor])

	// Belt-and-braces ordering — Append keeps insertion order which
	// is also SentAt order in normal operation, but if a future caller
	// ever appends out-of-order (race between in/out paths) the AI
	// rendering would look weird without this. Cheap on the small N.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].SentAt.Before(out[j].SentAt)
	})
	return out
}

// Len returns the current count of logged messages (peek, no copy).
// Used by /v1/status to surface "how much context the AI can recover".
func (l *MessageLog) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.messages)
}
