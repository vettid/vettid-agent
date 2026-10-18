package leash

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/pairing/pairtest"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

type prot struct{}

var protKey = make([]byte, 32)

func (prot) Name() string { return "test-key" }
func (prot) Wrap(k []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(protKey)
	n := make([]byte, a.NonceSize())
	return a.Seal(n, n, k, nil), nil
}
func (prot) Unwrap(w []byte) ([]byte, error) {
	a, _ := chacha20poly1305.NewX(protKey)
	if len(w) < a.NonceSize() {
		return nil, errors.New("short")
	}
	return a.Open(nil, w[:a.NonceSize()], w[a.NonceSize():], nil)
}
func (prot) Wipe() error { return nil }

func resolve(string) state.Protector { return prot{} }

// grantSpy notes, for each save whose record lacks the grant, how many
// messages were still unacknowledged at the relay.
type grantSpy struct {
	vaultconn.Store
	v      *pairtest.Vault
	id     string
	device string
	mu     sync.Mutex
	saves  []int // pending count of each save without the grant
}

func (g *grantSpy) Save(b []byte) error {
	if r, err := pairing.DecodeRecord(b); err == nil {
		if s, err := ReadSaved(r.Leash, g.device, time.Now()); err == nil && s != nil {
			has := false
			for _, gi := range s.Grants {
				has = has || gi.GrantID == g.id
			}
			if !has {
				g.mu.Lock()
				g.saves = append(g.saves, g.v.Pending())
				g.mu.Unlock()
			}
		}
	}
	return g.Store.Save(b)
}

func (g *grantSpy) first() (int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.saves) == 0 {
		return 0, false
	}
	return g.saves[0], true
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestOverVault: through vaultconn and a simulated vault, a
// leash.grant.updated that revokes a saved grant is saved in the record
// with its batch before the batch is acknowledged. At the next start the
// saved grant is shown as unconfirmed; the session check of
// internal/access (a leash.grant.list this package did not send) only
// narrows it away; Present's own list confirms the (empty) grants.
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

	type opened struct {
		c   *vaultconn.Conn
		m   *Manager
		a   *access.Manager
		rec *pairing.Record
	}
	run := func(wrap func(vaultconn.Store) vaultconn.Store, before func(o *opened), check func(o *opened)) {
		s, err := state.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		raw, err := s.Load(resolve)
		if err != nil {
			t.Fatal(err)
		}
		rec, _ := pairing.DecodeRecord(raw)
		var dev struct {
			DeviceID string `json:"device_id"`
		}
		_ = json.Unmarshal(rec.Device, &dev)
		o := &opened{rec: rec}
		o.m = New(Options{Saved: rec.Leash, OnAnswer: func(code string, sentWith pairing.Access) { o.a.OnAnswer(code, sentWith) }})
		var st vaultconn.Store = s
		if wrap != nil {
			st = wrap(s)
		}
		o.c, err = vaultconn.New(vaultconn.Options{Store: st, Resolve: resolve, Record: rec, HTTP: v.HTTPClient(),
			PollWait: 10 * time.Millisecond, Grants: o.m,
			OnEvent: func(ev vaultconn.Event) { o.a.OnEvent(ev) }, OnStatus: func(oc string) { o.a.OnStatus(oc); o.m.OnStatus(oc) }})
		if err != nil {
			t.Fatal(err)
		}
		o.a = access.New(o.c, 0, nil)
		if err := o.m.Bind(o.c); err != nil {
			t.Fatal(err)
		}
		if o.c.DeviceID() != dev.DeviceID {
			t.Fatal("device id")
		}
		if before != nil {
			before(o)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- o.c.Run(ctx) }()
		check(o)
		cancel()
		<-done
	}

	// A first run learns the device id and identity key and saves an
	// access session.
	var devID string
	var ik []byte
	run(nil, func(o *opened) {
		devID, ik = o.c.DeviceID(), o.c.IdentityKey()
		if _, err := v.SendEvent("device.session.granted", []byte(`{"session_id":"s1","expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)); err != nil {
			t.Fatal(err)
		}
	}, func(o *opened) {
		waitFor(t, "the session", func() bool { return o.c.Access().SessionID == "s1" && v.Pending() == 0 })
	})
	id1, id2 := gid(1), gid(2)
	g1 := grant(t, time.Now(), spec{id: id1, sub: ik, agentID: devID})
	g2 := grant(t, time.Now(), spec{id: id2, sub: ik, agentID: devID})
	// seed saves grants as an earlier run would have.
	seed := func(grants ...json.RawMessage) {
		m := New(Options{})
		f := &fakeConn{m: m, ik: ik, device: devID, access: pairing.Access{State: pairing.AccessActive},
			list: func() *vaultconn.Response { return ok(set(t, false, grants...)) }}
		if err := m.Bind(f); err != nil {
			t.Fatal(err)
		}
		if err := m.List(context.Background()); err != nil {
			t.Fatal(err)
		}
		s, _ := state.Open(dir)
		defer s.Close()
		raw, _ := s.Load(resolve)
		rec, _ := pairing.DecodeRecord(raw)
		rec.Leash = m.Snapshot()
		b, _ := rec.Encode()
		if err := s.Save(b); err != nil {
			t.Fatal(err)
		}
	}
	saved := func() []string {
		t.Helper()
		s, _ := state.Open(dir)
		defer s.Close()
		raw, _ := s.Load(resolve)
		rec, _ := pairing.DecodeRecord(raw)
		sv, err := ReadSaved(rec.Leash, devID, time.Now())
		if err != nil || sv == nil {
			t.Fatalf("saved grants: %+v %v", sv, err)
		}
		var ids []string
		for _, g := range sv.Grants {
			ids = append(ids, g.GrantID)
		}
		return ids
	}

	seed(g1, g2)
	sp := &grantSpy{v: v, id: id1, device: devID}
	run(func(s vaultconn.Store) vaultconn.Store { sp.Store = s; return sp }, func(o *opened) {
		if _, err := v.SendEvent("leash.grant.updated", set(t, false, g2)); err != nil { // gid(1) revoked
			t.Fatal(err)
		}
	}, func(o *opened) {
		waitFor(t, "the revocation saved", func() bool { _, ok := sp.first(); return ok })
		if p, _ := sp.first(); p == 0 {
			t.Error("the revocation was saved only after its batch was acknowledged")
		}
		in := o.m.ConnectionInfo()
		if len(in.Grants) != 1 || in.Grants[0].GrantID != id2 || in.GrantsConfirmed {
			t.Errorf("info after the event: %+v", in)
		}
	})
	if ids := saved(); len(ids) != 1 || ids[0] != id2 {
		t.Fatalf("file: %v", ids)
	}

	// Next start: shown as saved, unconfirmed; the session check at start
	// narrows (the vault lists none); Present's own list confirms.
	run(nil, nil, func(o *opened) {
		if in := o.m.ConnectionInfo(); len(in.Grants) != 1 || in.GrantsConfirmed {
			t.Errorf("info at start: %+v", in)
		}
		if err := o.a.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if in := o.m.ConnectionInfo(); len(in.Grants) != 0 || in.GrantsConfirmed {
			t.Errorf("info after the check: %+v", in)
		}
		if p, err := o.m.Present(context.Background(), id2); p != nil || !errors.Is(err, ErrNotGranted) {
			t.Errorf("present: %v", err)
		}
		if in := o.m.ConnectionInfo(); !in.GrantsConfirmed {
			t.Errorf("not confirmed by its own list: %+v", in)
		}
		if _, err := v.SendEvent("test.ping", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the batch", func() bool { return v.Pending() == 0 })
	})
	if ids := saved(); len(ids) != 0 {
		t.Errorf("file after the list: %v", ids)
	}
}
