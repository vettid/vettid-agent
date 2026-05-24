package api

import (
	"sync"
	"time"
)

// OwnerMessage is one chat message the vault owner sent to this agent
// via `agent.message-reply`. Surfaced over the local API for the
// embedded AI process to consume — GET /v1/messages/inbox drains the
// buffer; messages are NOT persisted to disk and are dropped when the
// daemon exits or when the buffer is read.
//
// We deliberately keep this minimal: no per-message read receipts back
// to the vault, no per-message acks. The AI process is short-lived and
// pulls when it's ready. If the AI doesn't pull, owner messages stack
// up in the bounded buffer until they're either drained or evicted.
type OwnerMessage struct {
	MessageID    string    `json:"message_id"`
	ReplyTo      string    `json:"reply_to,omitempty"`
	Content      string    `json:"content,omitempty"`
	Action       string    `json:"action,omitempty"` // "approve"/"deny" when this is an approval reply
	ReceivedAt   time.Time `json:"received_at"`
}

// MessageInbox is a thread-safe ring of recent owner→agent messages.
// Bounded to keep a buggy AI process from leaking memory if it never
// drains: oldest messages are evicted when the cap is hit, with a
// counter exposed via the inbox payload so the consumer can detect
// drops.
type MessageInbox struct {
	mu       sync.Mutex
	messages []OwnerMessage
	dropped  uint64
	cap      int
}

// inboxCapDefault keeps the buffer bounded but generous enough that a
// short-running AI process picking up after a few owner messages doesn't
// hit eviction. Sized for a chatty owner + slow drainer.
const inboxCapDefault = 256

func NewMessageInbox() *MessageInbox {
	return &MessageInbox{cap: inboxCapDefault}
}

// Push appends a message, evicting the oldest if the buffer is full.
// Eviction increments the dropped counter so Drain can report it.
func (m *MessageInbox) Push(msg OwnerMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.messages) >= m.cap {
		m.messages = m.messages[1:]
		m.dropped++
	}
	m.messages = append(m.messages, msg)
}

// Drain returns all pending messages and clears the buffer, plus the
// running dropped-since-last-drain counter. After Drain returns, the
// inbox is empty and the dropped counter resets — the AI process owns
// the returned slice.
func (m *MessageInbox) Drain() ([]OwnerMessage, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.messages
	dropped := m.dropped
	m.messages = nil
	m.dropped = 0
	return out, dropped
}

// Peek returns a copy of the current buffer without draining. Used by
// the status endpoint so callers can see "how many messages are
// waiting" without consuming them.
func (m *MessageInbox) Peek() ([]OwnerMessage, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]OwnerMessage, len(m.messages))
	copy(out, m.messages)
	return out, m.dropped
}
