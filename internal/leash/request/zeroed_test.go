package request

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// TestBodyZeroedBeforeAnswer: when a request's waiter is woken (finish),
// every response body the vault connection handed out is already zero,
// for an answer and for a refusal that carries a body. finishHook checks
// at that moment, so clearing the body only after finish (as a defer
// would) fails here every time.
func TestBodyZeroedBeforeAnswer(t *testing.T) {
	answers := []*vaultconn.Response{
		ok(itemBody),
		{Type: "agent.request", ErrorCode: "denied", Body: json.RawMessage(`{"detail":"` + secret + `"}`)},
	}
	var mu sync.Mutex
	var dirty []string
	var e *env
	finishHook = func() {
		e.conn.mu.Lock()
		defer e.conn.mu.Unlock()
		for _, b := range e.conn.bodies {
			if len(bytes.Trim(b, "\x00")) != 0 {
				mu.Lock()
				dirty = append(dirty, string(b))
				mu.Unlock()
			}
		}
	}
	t.Cleanup(func() { finishHook = nil })
	e = newEnv(t, func(n int, _ string) (*vaultconn.Response, error) { return answers[n-1], nil }, nil)
	if out, err := e.c.Get(context.Background(), itemID, nil); err != nil || out.Result == nil {
		t.Fatalf("answer: %+v, %v", out, err)
	}
	if _, err := e.c.Get(context.Background(), itemID, nil); err == nil {
		t.Fatal("a refusal answered")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(dirty) != 0 {
		t.Fatalf("bodies not zero when the waiter was woken: %q", dirty)
	}
	for _, b := range e.conn.bodies {
		if len(bytes.Trim(b, "\x00")) != 0 {
			t.Fatal("a body was not zeroed")
		}
	}
	if len(e.conn.bodies) != 2 {
		t.Fatalf("%d bodies handed out", len(e.conn.bodies))
	}
}
