package access_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
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

// TestStartProbeOverVault: after pairing the session is unknown; a
// grant arrives and is saved; at the next start the saved session is
// checked with leash.grant.list against the vault, which says it was
// ended (session_required); the session becomes none and is saved with
// the next batch.
func TestStartProbeOverVault(t *testing.T) {
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
	if _, err := v.SendEvent("device.session.granted", []byte(`{"session_id":"s1","expires_at":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`"}`)); err != nil {
		t.Fatal(err)
	}

	run := func(check func(c *vaultconn.Conn, m *access.Manager)) {
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
		var m *access.Manager
		c, err := vaultconn.New(vaultconn.Options{Store: s, Resolve: resolve, Record: rec, HTTP: v.HTTPClient(),
			PollWait: 10 * time.Millisecond, OnEvent: func(ev vaultconn.Event) { m.OnEvent(ev) }, OnStatus: func(oc string) { m.OnStatus(oc) }})
		if err != nil {
			t.Fatal(err)
		}
		m = access.New(c, 0, nil)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.Run(ctx) }()
		check(c, m)
		cancel()
		<-done
	}
	wait := func(what string, f func() bool) {
		deadline := time.Now().Add(10 * time.Second)
		for !f() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out: %s", what)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	run(func(c *vaultconn.Conn, m *access.Manager) {
		wait("the grant", func() bool { return c.Access().SessionID == "s1" })
		if err := m.Ensure(context.Background()); err != nil {
			t.Errorf("Ensure with a session: %v", err)
		}
	})
	v.GrantListError = "session_required"
	run(func(c *vaultconn.Conn, m *access.Manager) {
		if a := c.Access(); a.SessionID != "s1" {
			t.Fatalf("saved session not loaded: %+v", a)
		}
		if err := m.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if a := c.Access(); a.State != pairing.AccessNone {
			t.Fatalf("after the probe: %+v", a)
		}
		if _, err := v.SendEvent("test.ping", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		wait("the batch", func() bool { return v.Pending() == 0 })
	})
	s2, _ := state.Open(dir)
	raw, _ := s2.Load(resolve)
	rec, _ := pairing.DecodeRecord(raw)
	s2.Close()
	if rec.Access.State != pairing.AccessNone {
		t.Errorf("saved: %+v", rec.Access)
	}
}
