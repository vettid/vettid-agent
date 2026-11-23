package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

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

// The connector's session gives the grants the vault's word: with the
// vault naming a session this computer's clock puts in the past,
// leash.connection_info shows it as active once the start's check has
// answered, as tool calls use it.
func TestSessionGrantsTakeVaultWord(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	v.StatusSession = `{"session_id":"s-ahead","expires_at":"` + time.Now().Add(-10*time.Minute).UTC().Format(time.RFC3339) + `"}`
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	withTestMCP(t, v, inR)
	var errOut syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"mcp", "--state-dir", dir}, outW, &errOut)
		outW.Close()
	}()
	client := sdk.NewClient(&sdk.Implementation{Name: "vettid-agent-test", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cs.Close()
		inW.Close()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("mcp did not exit")
		}
	}()
	var sc map[string]any
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		sc, _ = callTool(t, cs, "leash.connection_info", nil)
		if sc["access_session"] != "unknown" {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("still unknown: %v", sc)
		}
	}
	if sc["access_session"] != "active" {
		t.Fatalf("connection_info %v, want active on the vault's word (stderr %s)", sc, errOut.String())
	}
}
