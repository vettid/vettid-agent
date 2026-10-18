package vaultconn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
)

// recPart records what Apply saw and gives a snapshot counting the
// batches.
type recPart struct {
	mu   sync.Mutex
	seen []Message
	n    int
}

func (p *recPart) Apply(b []Message) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, b...)
	p.n++
}

func (p *recPart) Snapshot() json.RawMessage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return json.RawMessage(fmt.Sprintf(`{"batches":%d}`, p.n))
}

func (p *recPart) find(typ string, response bool) (Message, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.seen {
		if m.Type == typ && (m.Re != "") == response {
			return m, true
		}
	}
	return Message{}, false
}

// leashSpy notes the `leash` member of each save and the messages still
// unacknowledged at the relay then.
type leashSpy struct {
	Store
	pending func() int
	mu      sync.Mutex
	saves   []string
}

func (s *leashSpy) Save(b []byte) error {
	if r, err := pairing.DecodeRecord(b); err == nil {
		s.mu.Lock()
		s.saves = append(s.saves, fmt.Sprintf("%s/%d", r.Leash, s.pending()))
		s.mu.Unlock()
	}
	return s.Store.Save(b)
}

func (s *leashSpy) last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.saves) == 0 {
		return ""
	}
	return s.saves[len(s.saves)-1]
}

// openWith opens the state directory as e.open does, with part as
// Options.Grants (nil: none).
func (e *env) openWith(part Part, sp *leashSpy) *opened {
	e.t.Helper()
	s, err := state.Open(e.dir)
	if err != nil {
		e.t.Fatal(err)
	}
	raw, err := s.Load(e.resolve)
	if err != nil {
		s.Close()
		e.t.Fatal(err)
	}
	rec, err := pairing.DecodeRecord(raw)
	if err != nil {
		s.Close()
		e.t.Fatal(err)
	}
	sp.Store, sp.pending = s, e.v.Pending
	o := &opened{store: s, rec: rec, evs: make(chan Event, 100)}
	o.conn, err = New(Options{Store: sp, Resolve: e.resolve, Record: rec, Out: e.out, HTTP: e.v.HTTPClient(),
		Log: slog.New(slog.NewTextHandler(e.log, nil)), PollWait: 10 * time.Millisecond,
		OnEvent: func(ev Event) { o.evs <- ev }, Grants: part})
	if err != nil {
		s.Close()
		e.t.Fatal(err)
	}
	return o
}

// TestPartAppliedInSave: Options.Grants sees each batch's events and
// responses inside its save, and its snapshot is saved as the record's
// `leash` member before the batch is acknowledged.
func TestPartAppliedInSave(t *testing.T) {
	e := newPaired(t)
	p := &recPart{}
	sp := &leashSpy{}
	o := e.openWith(p, sp)
	if len(o.conn.IdentityKey()) != 32 || !o.conn.LastContact().IsZero() {
		t.Fatal("identity key or last contact")
	}
	if _, err := e.v.SendEvent("leash.grant.updated", []byte(`{"grants":[],"suspended":false}`)); err != nil {
		t.Fatal(err)
	}
	stop := o.run()
	defer stop()
	nextEvent(t, o, "leash.grant.updated")
	if _, ok := p.find("leash.grant.updated", false); !ok {
		t.Fatal("the event was not applied")
	}
	if l := sp.last(); !bytes.HasPrefix([]byte(l), []byte(`{"batches":`)) || bytes.HasSuffix([]byte(l), []byte("/0")) {
		t.Errorf("saved %q: not the snapshot, or after the acknowledgement", l)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := o.conn.Request(ctx, "leash.grant.list", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if m, ok := p.find("leash.grant.list", true); !ok || !m.OK || m.Re == "" {
		t.Errorf("the response was not applied before it was handed over: %+v", m)
	}
	if o.conn.LastContact().IsZero() {
		t.Error("no last contact")
	}
}

// TestPartAbsentKeepsMember: without Options.Grants the record's
// `leash` member is saved again as loaded.
func TestPartAbsentKeepsMember(t *testing.T) {
	e := newPaired(t)
	s, _ := state.Open(e.dir)
	raw, _ := s.Load(e.resolve)
	rec, _ := pairing.DecodeRecord(raw)
	rec.Leash = json.RawMessage(`{"kept":true}`)
	b, _ := rec.Encode()
	if err := s.Save(b); err != nil {
		t.Fatal(err)
	}
	s.Close()
	sp := &leashSpy{}
	o := e.openWith(nil, sp)
	if _, err := e.v.SendEvent("test.ping", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	stop := o.run()
	nextEvent(t, o, "test.ping")
	stop()
	if l := sp.last(); !bytes.HasPrefix([]byte(l), []byte(`{"kept":true}/`)) {
		t.Errorf("saved %q", l)
	}
}

// TestRequestWithIDEmpty: an empty id is accepted (the client chooses
// one) and answered; a non-ULID id is refused before anything is sent.
func TestRequestWithIDEmpty(t *testing.T) {
	e := newPaired(t)
	o := e.openWith(nil, &leashSpy{})
	stop := o.run()
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := o.conn.RequestWithID(ctx, "", "leash.grant.list", json.RawMessage(`{}`))
	if err != nil || !r.OK {
		t.Fatalf("empty id: %+v %v", r, err)
	}
	before := count(e.v.Received(), "leash.grant.list")
	if _, err := o.conn.RequestWithID(ctx, "01jb2z6v9k3m4n5p6q7r8s9t41", "leash.grant.list", json.RawMessage(`{}`)); err == nil {
		t.Error("a non-ULID id (lower case) was accepted")
	}
	if n := count(e.v.Received(), "leash.grant.list"); n != before {
		t.Error("a refused id was sent")
	}
}
