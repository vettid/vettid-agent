package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/leash/request"
	"github.com/vettid/vettid-agent/internal/mcp"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// session is the connector's MCP session for one paired record: its
// vault connection, access policy, grants and requests, and the MCP
// server reading In and writing Out. `vettid-agent mcp` runs one over its
// standard input and output; the connector service (AGENT-PLAN §6
// A3.10b) runs one per stub, over the channel.
type session struct {
	Store         *state.Store
	Resolve       state.Resolver
	Record        *pairing.Record
	AccessMinutes int
	// Log is for diagnostics; Notices is where the vault connection tells
	// the operator what it did (standard error for `mcp`).
	Log     *slog.Logger
	Notices io.Writer
	// In and Out carry the MCP messages and nothing else.
	In  io.Reader
	Out io.Writer
}

// run runs the session until In ends or ctx ends (it then returns
// context.Canceled) or the vault connection stops (its error). When it
// returns, nothing of the session writes to Out or Notices any more,
// except that a write to Out that its reader does not take is abandoned
// after a bounded wait (stopSession). The results it kept are zeroed.
func (s session) run(ctx context.Context) error {
	logger := s.Log
	// The access policy (AG8) and the agent's requests see each event,
	// and the access policy each vault.status; they are created once the
	// connection exists (the callbacks run only in Run).
	var mgr *access.Manager
	var reqs *request.Client
	grants := newGrants(s.Record, logger, func(code string, sentWith pairing.Access) { mgr.OnAnswer(code, sentWith) })
	o := vaultconn.Options{
		Store:   s.Store,
		Resolve: s.Resolve,
		Record:  s.Record,
		Out:     s.Notices,
		Log:     logger,
		OnEvent: func(ev vaultconn.Event) {
			mgr.OnEvent(ev)
			reqs.OnEvent(ev)
		},
		OnStatus: func(oc string) {
			mgr.OnStatus(oc)
			grants.OnStatus(oc)
		},
		Grants: grants,
	}
	if mcpOptions != nil {
		mcpOptions(&o)
	}
	conn, err := vaultconn.New(o)
	if err != nil {
		return err
	}
	mgr = access.New(conn, s.AccessMinutes*60, nil)
	// A vault.status sent while the vault is held (CheckHold) also ends
	// the grants' hold.
	mgr.SetStatusHook(grants.OnStatus)
	// Every grant must name this device (the client's device id); without
	// one nothing could be checked, so the connector does not run.
	if err := grants.Bind(conn); err != nil {
		return err
	}
	ro := request.Options{Log: logger, Suspended: grants.Suspended, OnForbidden: grants.Relist}
	if mcpRequestOptions != nil {
		mcpRequestOptions(&ro)
	}
	reqs = request.New(conn, mgr, ro)
	// Closed last: it zeroes every result still kept.
	defer reqs.Close()
	held := func() bool { return mgr.Held() || grants.Held() }
	srv := mcp.New(mcp.Options{
		Requests: reqs,
		Info:     grants.ConnectionInfo,
		Held:     held,
		// While the vault is held, a tool call asks it again whether it
		// still is, at most once a minute (AGENT-PLAN §4.4).
		BeforeCall: func() {
			if held() {
				mgr.CheckHold()
			}
		},
		Version: readVersion().Version,
		Log:     logger,
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The MCP session: In and Out carry its messages and nothing else.
	// The MCP client ends it by closing In.
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		if err := srv.Serve(ctx, s.In, s.Out); err != nil && ctx.Err() == nil {
			logger.Warn("MCP input failed", "err", "read error")
		}
		cancel()
	}()
	// A saved session that has not expired is checked once at start
	// (internal/access Start), through Run's goroutine.
	startDone := make(chan struct{})
	go func() {
		defer close(startDone)
		if err := mgr.Start(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("access session check at start failed", "err", err)
		}
	}()
	// The grants' status statements are kept fresh (internal/leash Run).
	grantsDone := make(chan struct{})
	go func() {
		defer close(grantsDone)
		grants.Run(ctx)
	}()
	err = conn.Run(ctx)
	// The check ends with Run (its request fails once Run stops); wait
	// for it, and for the MCP session (whose tool calls end with ctx),
	// so that nothing writes to Out or Notices after return; except that
	// a write to Out that the MCP client does not read is abandoned after
	// a bounded wait (stopSession).
	cancel()
	<-startDone
	stopSession(serveDone, s.Out, logger)
	<-grantsDone
	// Requests the access manager still runs in the background end at
	// once now that Run has (vaultconn answers ErrStopped).
	mgr.Wait()
	return err
}
