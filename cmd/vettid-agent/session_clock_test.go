package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
)

// A session starts with its saved access session suspect (it is checked
// with the vault before use, as after a resume), and watches the clocks
// while it runs.
func TestSessionStartsSuspectAndWatchesClock(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	inR, inW := io.Pipe()
	withTestMCP(t, v, inR)
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	resolve := func(string) state.Protector { return cmdTestProtector{} }
	raw, err := store.Load(resolve)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := pairing.DecodeRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *access.Manager, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- session{Store: store, Resolve: resolve, Record: rec, AccessMinutes: 60,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Notices: io.Discard, In: inR, Out: io.Discard,
			OnManager: func(m *access.Manager) { got <- m }}.run(ctx)
	}()
	defer func() {
		cancel()
		inW.Close()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("the session did not end")
		}
	}()
	var m *access.Manager
	select {
	case m = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("the session never gave its access manager")
	}
	if !m.Suspected() {
		t.Error("a new session's saved access session is not suspect")
	}
	for end := time.Now().Add(5 * time.Second); !m.Watching(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the session does not watch the clocks")
		}
	}
}
