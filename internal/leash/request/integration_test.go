package request_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/leash/request"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/pairing/pairtest"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

type prot struct{}

var key = make([]byte, 32)

func (prot) Name() string { return "test-key" }
func (prot) Wrap(k []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(key)
	n := make([]byte, a.NonceSize())
	return a.Seal(n, n, k, nil), nil
}
func (prot) Unwrap(w []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(key)
	if len(w) < a.NonceSize() {
		return nil, errors.New("short")
	}
	return a.Open(nil, w[:a.NonceSize()], w[a.NonceSize():], nil)
}
func (prot) Wipe() error { return nil }

func resolve(string) state.Protector { return prot{} }

const (
	item   = "01JB2Z6V9K3M4N5P6Q7R8S9XYZ"
	secret = "integration-S3cret-Value"
)

// TestOverVault drives the requests through a real vaultconn.Conn and
// the client's envelopes (pairtest's relay and vault side), as
// `vettid-agent mcp` runs them:
//
//   - a referred item.get: approval.waiting arrives as an event, the
//     tool call returns pending, the approval's answer arrives later and
//     Status returns the value; one copy was sent;
//   - an item.get whose first copy goes unanswered (a locked vault): it
//     is sent again under the same inner id, and that copy's answer is
//     returned;
//   - the state file, decrypted, never holds the item's value.
func TestOverVault(t *testing.T) {
	v, err := pairtest.New()
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	dir := filepath.Join(t.TempDir(), "state")
	code, _ := v.Code(invite.KindAgent, 10*time.Minute)
	s, _ := state.Open(dir)
	err = pairing.Pair(context.Background(), pairing.Options{Store: s, Resolve: resolve,
		Protector: func() (state.Protector, string, error) { return prot{}, "", nil },
		Code:      func() (string, error) { return code, nil }, Name: "t", Out: &bytes.Buffer{},
		HTTP: v.HTTPClient(), PollWait: 10 * time.Millisecond})
	s.Close()
	if err != nil {
		t.Fatal(err)
	}

	type got struct{ id, typ string }
	var mu sync.Mutex
	var reqs []got
	var mode string
	v.OnRequest = func(id, typ string, body []byte) {
		mu.Lock()
		reqs = append(reqs, got{id, typ})
		m := mode
		mu.Unlock()
		if typ != "agent.request" || m != "refer" {
			return
		}
		exp := time.Now().Add(5 * time.Second).UTC().Format(time.RFC3339Nano)
		_, _ = v.SendEvent("approval.waiting", []byte(`{"approval_id":"01JB2Z6V9K3M4N5P6Q7R8S9APP","request_id":"`+id+`","exp":"`+exp+`"}`))
	}
	agentReqs := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var ids []string
		for _, r := range reqs {
			if r.typ == "agent.request" {
				ids = append(ids, r.id)
			}
		}
		return ids
	}
	wait := func(what string, f func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !f() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out: %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	itemBody := []byte(`{"item_id":"` + item + `","name":"n","category":"login","fields":[{"field_id":"pw","label":"Password","kind":"password","value":"` + secret + `"}]}`)

	s, err = state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Load(resolve)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := pairing.DecodeRecord(raw)
	var mgr *access.Manager
	var reqc *request.Client
	conn, err := vaultconn.New(vaultconn.Options{Store: s, Resolve: resolve, Record: rec, HTTP: v.HTTPClient(),
		PollWait: 10 * time.Millisecond,
		OnEvent: func(ev vaultconn.Event) {
			mgr.OnEvent(ev)
			reqc.OnEvent(ev)
		},
		OnStatus: func(oc string) { mgr.OnStatus(oc) }})
	if err != nil {
		t.Fatal(err)
	}
	mgr = access.New(conn, 0, nil)
	reqc = request.New(conn, mgr, request.Options{Wait: 300 * time.Millisecond, Attempt: 500 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- conn.Run(ctx) }()
	if _, err := v.SendEvent("device.session.granted", []byte(`{"session_id":"s1","expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)); err != nil {
		t.Fatal(err)
	}
	wait("the session", func() bool { return conn.Access().SessionID == "s1" })

	// Referred, then approved.
	mu.Lock()
	mode = "refer"
	mu.Unlock()
	out, err := reqc.Get(context.Background(), item, nil)
	if err != nil || !out.Pending || !out.Waiting {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	time.Sleep(700 * time.Millisecond) // past Attempt: still waiting, not sent again
	if ids := agentReqs(); len(ids) != 1 || ids[0] != out.RequestID {
		t.Fatalf("copies while held: %v", ids)
	}
	if _, err := v.SendResponse(out.RequestID, "agent.request", itemBody, ""); err != nil {
		t.Fatal(err)
	}
	var res *request.Outcome
	wait("the result", func() bool {
		res, err = reqc.Status(context.Background(), out.RequestID)
		return err != nil || !res.Pending
	})
	if err != nil || res.Result == nil || string(res.Result.Item.Fields[0].Value) != `"`+secret+`"` {
		t.Fatalf("Status: %+v, %v", res, err)
	}
	res.Result.Wipe()

	// Unanswered first copy: sent again under the same id.
	mu.Lock()
	mode = "silent"
	mu.Unlock()
	out, err = reqc.Get(context.Background(), item, []string{"pw"})
	if err != nil || !out.Pending || out.Waiting {
		t.Fatalf("Get: %+v, %v", out, err)
	}
	wait("the second copy", func() bool { return len(agentReqs()) == 3 })
	if ids := agentReqs(); ids[1] != out.RequestID || ids[2] != out.RequestID {
		t.Fatalf("copies: %v (request %s)", ids, out.RequestID)
	}
	if _, err := v.SendResponse(out.RequestID, "agent.request", itemBody, ""); err != nil {
		t.Fatal(err)
	}
	wait("the result", func() bool {
		res, err = reqc.Status(context.Background(), out.RequestID)
		return err != nil || !res.Pending
	})
	if err != nil || res.Result == nil {
		t.Fatalf("Status: %+v, %v", res, err)
	}
	res.Result.Wipe()

	// A batch after the answers, so that their batch's save is behind
	// us; then stop and read the state file back.
	if _, err := v.SendEvent("test.ping", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	wait("the mailbox to drain", func() bool { return v.Pending() == 0 })
	reqc.Close()
	cancel()
	<-done
	s.Close()
	s, _ = state.Open(dir)
	defer s.Close()
	raw, err = s.Load(resolve)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pairing.DecodeRecord(raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Error("the state file holds the item's value")
	}
}
