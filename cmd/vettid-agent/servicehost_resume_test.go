package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// noVault is an access.Conn that answers nothing.
type noVault struct{}

func (noVault) Request(context.Context, string, json.RawMessage) (*vaultconn.Response, error) {
	return nil, errors.New("no vault")
}
func (noVault) Access() pairing.Access                       { return pairing.Access{State: pairing.AccessNone} }
func (noVault) CompareAndSetAccess(_, _ pairing.Access) bool { return false }

// A resume from sleep reaches the stub's session's access manager while
// the session runs, and nothing after it has ended.
func TestHostResumedSuspectsSession(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	pairOptions = nil
	m := access.New(noVault{}, 0, nil)
	running := make(chan struct{})
	release := make(chan struct{})
	h := &serviceHost{Dir: dir, IdleStop: time.Minute, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Protectors: &pairing.Protectors{NoPrompt: true, Dir: dir},
		resolve:    func(string) state.Protector { return cmdTestProtector{} },
		runSessionFn: func(_ context.Context, s session) error {
			s.OnManager(m)
			defer s.OnManager(nil)
			close(running)
			<-release
			return nil
		}}
	th := &testHost{h: h, clients: make(chan *hostConn), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		th.done <- h.Serve(ctx, func(ctx context.Context) (*hostConn, error) {
			select {
			case c := <-th.clients:
				return c, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}()
	t.Cleanup(func() { cancel(); <-th.done })
	h.Resumed() // no session yet: nothing to tell
	fc := th.connect(t, channel.OpMCP)
	fc.waitAnswer(t)
	select {
	case <-running:
	case <-time.After(10 * time.Second):
		t.Fatal("the session did not start")
	}
	if m.Suspected() {
		t.Fatal("suspect before any resume")
	}
	h.Resumed()
	if !m.Suspected() {
		t.Fatal("the running session's access manager was not told of the resume")
	}
	close(release)
	select {
	case <-fc.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not end")
	}
	h.mu.Lock()
	left := h.mgr
	h.mu.Unlock()
	if left != nil {
		t.Fatal("the ended session's manager is still registered")
	}
}
