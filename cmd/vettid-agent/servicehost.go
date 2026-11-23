package main

// The connector service's host (AGENT-PLAN §6 A3.10b; AGENT-SEPARATE-ACCOUNT
// §2, §5): it holds the pairing's state directory, takes the channel's
// admitted clients and runs each one's operation: an MCP session for a
// stub (one at a time), the status, and the elevated pair and forget. It
// stops a while after the last client leaves, unless something holds it
// (runs, A3.10c). The platform's service glue (service_windows.go) gives
// it the clients and stops it.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/leash/request"
	"github.com/vettid/vettid-agent/internal/mcp"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/protect"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// The service's answer to tools while it holds no finished pairing
// (chosen; not in the spec).
const (
	codeNotPaired = "not_paired"
	textNotPaired = "This connector is not paired with your vault yet. Ask your administrator to run `vettid-agent pair --name <name>` as administrator, as the README says."
)

// defaultIdleStop is how long the service runs once nothing holds it
// (chosen; not in the spec: "a while", AGENT-SEPARATE-ACCOUNT §5).
const defaultIdleStop = 5 * time.Minute

var (
	// requestWait bounds status, forget and pair until their request
	// line is read (status and forget for their whole exchange), so that
	// a client that says nothing holds neither a place nor the stop
	// (chosen; not in the spec).
	requestWait = 10 * time.Second
	// preemptWait bounds how long an administrator's pair or forget waits
	// for the stub's session it ended (chosen; not in the spec; the
	// session's own stop is bounded by 2 × mcpStopWait).
	preemptWait = 10 * time.Second
)

// hostConn is one admitted client of the channel.
type hostConn struct {
	rw          io.ReadWriter
	op          channel.Op
	accept      func() error          // the operation may start
	refuse      func(err error) error // refused, and closed
	close       func() error          // may be called more than once
	setDeadline func(time.Time) error
}

// serviceHost runs one pairing's connector service.
type serviceHost struct {
	// Dir is the state directory, private to the service's account.
	Dir string
	// AccessMinutes is the access session asked for (mcp's
	// --access-minutes; the service's configuration).
	AccessMinutes int
	// IdleStop is how long the host keeps running with nothing holding
	// it; 0 means defaultIdleStop.
	IdleStop time.Duration
	Log      *slog.Logger
	// Protectors gives the state's protector (DPAPI of the service's
	// account on Windows). It never prompts.
	Protectors *pairing.Protectors
	// pairOptions adjusts a pairing's options (tests).
	pairOptions func(*pairing.Options)

	store *state.Store

	mu sync.Mutex
	// The stub's session, if one runs: end ends it, and done is closed
	// once it has.
	mcpActive bool
	mcpEnd    context.CancelFunc
	mcpDone   chan struct{}
	exclusive bool // pair or forget runs, or waits for the stub's session to end
	holds     int  // clients being served, and what else holds the host
	conns     map[*hostConn]struct{}
	idle      chan struct{}
}

// Hold keeps the host from stopping until the matching Release: each
// client, and (A3.10c) each run in flight and each run answer still kept.
func (h *serviceHost) Hold() {
	h.mu.Lock()
	h.holds++
	h.mu.Unlock()
}

// Release ends one Hold. When nothing holds the host any more, its idle
// time starts.
func (h *serviceHost) Release() {
	h.mu.Lock()
	h.holds--
	if h.holds < 0 {
		h.mu.Unlock()
		panic("serviceHost: Release without Hold")
	}
	zero := h.holds == 0
	h.mu.Unlock()
	if zero {
		select {
		case h.idle <- struct{}{}:
		default:
		}
	}
}

// Held reports how many holds the host has (status, tests).
func (h *serviceHost) Held() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.holds
}

// errIdle: the host stopped because nothing held it for IdleStop.
var errIdle = errors.New("idle")

func (h *serviceHost) track(c *hostConn) {
	h.mu.Lock()
	if h.conns == nil {
		h.conns = map[*hostConn]struct{}{}
	}
	h.conns[c] = struct{}{}
	h.mu.Unlock()
}

func (h *serviceHost) untrack(c *hostConn) {
	h.mu.Lock()
	delete(h.conns, c)
	h.mu.Unlock()
}

// closeAll closes every client still being served: on stop, nothing a
// client does or fails to do (read its answers, send its request) keeps
// its handler, and so the stop, waiting.
func (h *serviceHost) closeAll() {
	h.mu.Lock()
	cs := make([]*hostConn, 0, len(h.conns))
	for c := range h.conns {
		cs = append(cs, c)
	}
	h.mu.Unlock()
	for _, c := range cs {
		_ = c.close()
	}
}

// Serve opens the state directory and serves the clients accept returns
// until ctx ends (it then returns ctx's error), accept fails (its error),
// or nothing has held the host for IdleStop (errIdle). When it returns,
// every client has been closed, every operation has ended, and the state
// directory is closed.
//
// The idle stop stops taking clients first; a client accept had already
// handed over is served, and the host stops once it and every other hold
// have ended. A client the channel admitted but accept had not handed
// over is closed with the channel, unanswered; the stub then starts the
// service again (startService).
func (h *serviceHost) Serve(ctx context.Context, accept func(context.Context) (*hostConn, error)) error {
	store, err := state.Open(h.Dir)
	if err != nil {
		return err
	}
	h.store = store
	defer store.Close()
	if h.idle == nil {
		h.idle = make(chan struct{}, 1)
	}
	idleStop := h.IdleStop
	if idleStop <= 0 {
		idleStop = defaultIdleStop
	}
	ctx, cancel := context.WithCancelCause(ctx)
	acceptCtx, stopAccept := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel(nil)
		stopAccept()
		h.closeAll()
		wg.Wait()
	}()
	acceptDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(acceptDone)
		for {
			c, err := accept(acceptCtx)
			if err != nil {
				if acceptCtx.Err() == nil {
					cancel(err)
				}
				return
			}
			h.Hold()
			h.track(c)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer h.Release()
				defer h.untrack(c)
				h.handle(ctx, c)
			}()
		}
	}()
	t := time.NewTimer(idleStop)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-h.idle:
			if h.Held() == 0 {
				t.Reset(idleStop)
			}
		case <-t.C:
			if h.Held() != 0 {
				continue
			}
			// Stop taking clients; one handed over meanwhile is served.
			stopAccept()
			<-acceptDone
			for h.Held() != 0 {
				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				case <-h.idle:
				}
			}
			return errIdle
		}
	}
}

// handle runs one client's operation and closes it.
func (h *serviceHost) handle(ctx context.Context, c *hostConn) {
	switch c.op {
	case channel.OpMCP:
		sessCtx, end := context.WithCancel(ctx)
		defer end()
		done := make(chan struct{})
		if !h.claimSession(end, done) {
			_ = c.refuse(channel.ErrInUse)
			return
		}
		// The stub's connection is closed before its place is given back:
		// a pair or forget that ended it then runs with the stub gone.
		defer h.releaseSession(done)
		defer c.close()
		if c.accept() != nil {
			return
		}
		h.runSession(sessCtx, c.rw)
	case channel.OpStatus:
		defer c.close()
		_ = c.setDeadline(time.Now().Add(requestWait))
		if c.accept() != nil {
			return
		}
		h.status(c.rw)
	case channel.OpPair, channel.OpForget:
		if !h.claimExclusive(ctx, c.op) {
			_ = c.refuse(channel.ErrInUse)
			return
		}
		// The place is given back before the client is closed, so that a
		// stub that connects once it sees the close is served.
		defer c.close()
		defer h.releaseExclusive()
		_ = c.setDeadline(time.Now().Add(requestWait))
		if c.accept() != nil {
			return
		}
		if c.op == channel.OpPair {
			h.pair(ctx, c.rw, func() { _ = c.setDeadline(time.Time{}) })
		} else {
			h.forget(c.rw)
		}
	default:
		_ = c.refuse(channel.ErrNotAllowed)
	}
}

// claimSession takes the stub's place: one stub at a time, and none while
// pair or forget runs or waits.
func (h *serviceHost) claimSession(end context.CancelFunc, done chan struct{}) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mcpActive || h.exclusive {
		return false
	}
	h.mcpActive, h.mcpEnd, h.mcpDone = true, end, done
	return true
}

func (h *serviceHost) releaseSession(done chan struct{}) {
	h.mu.Lock()
	h.mcpActive, h.mcpEnd, h.mcpDone = false, nil, nil
	h.mu.Unlock()
	close(done)
}

// claimExclusive takes pair's or forget's place. An administrator's pair
// or forget comes before the member's agent: a stub's session that runs
// is ended first, and no new stub is taken meanwhile. It fails only if
// another pair or forget runs, or the session did not end within
// preemptWait.
func (h *serviceHost) claimExclusive(ctx context.Context, op channel.Op) bool {
	h.mu.Lock()
	if h.exclusive {
		h.mu.Unlock()
		return false
	}
	h.exclusive = true
	end, done := h.mcpEnd, h.mcpDone
	h.mu.Unlock()
	if done == nil {
		return true
	}
	h.Log.Info("an administrator's command ends the stub's session", "op", string(op))
	end()
	t := time.NewTimer(preemptWait)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
	case <-ctx.Done():
	}
	h.releaseExclusive()
	return false
}

func (h *serviceHost) releaseExclusive() {
	h.mu.Lock()
	h.exclusive = false
	h.mu.Unlock()
}

// runSession serves one stub: the paired record's MCP session over rw,
// or, with no finished pairing, every tool answered not_paired. It ends
// when ctx does, within stopSession's bounds.
func (h *serviceHost) runSession(ctx context.Context, rw io.ReadWriter) {
	logger := h.Log
	rec, err := h.loadRecord()
	if err != nil {
		logger.Warn("no MCP session", "code", codeNotPaired)
		srv := mcp.New(mcp.Options{Unavailable: &request.Error{Code: codeNotPaired, Text: textNotPaired}, Version: readVersion().Version, Log: logger})
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = srv.Serve(ctx, rw, rw)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			stopSession(done, rw, logger)
		}
		return
	}
	defer func() {
		clear(rec.Device)
		clear(rec.Leash)
	}()
	err = session{
		Store:         h.store,
		Resolve:       h.Protectors.Resolve,
		Record:        rec,
		AccessMinutes: h.AccessMinutes,
		Log:           logger,
		// The vault connection's notices are for a terminal, and a
		// service has none; its log carries ids and codes only.
		Notices: io.Discard,
		In:      rw,
		Out:     rw,
	}.run(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Warn("the MCP session ended", "err", err)
	}
}

// loadRecord reads the finished pairing. The caller clears its Device
// and Leash when done; a record that is not paired is cleared here.
func (h *serviceHost) loadRecord() (*pairing.Record, error) {
	ok, err := h.store.Exists()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, vaultconn.ErrNotPaired
	}
	raw, err := h.store.Load(h.Protectors.Resolve)
	if err != nil {
		return nil, fmt.Errorf("the state file cannot be opened: %w", err)
	}
	rec, err := pairing.DecodeRecord(raw)
	clear(raw)
	if err != nil {
		return nil, err
	}
	if rec.Phase != pairing.PhasePaired {
		clear(rec.Device)
		clear(rec.Leash)
		return nil, vaultconn.ErrNotPaired
	}
	return rec, nil
}

// status answers `status --name`: what status shows for a state
// directory, read without the vault.
func (h *serviceHost) status(rw io.ReadWriter) {
	out := &consoleWriter{w: rw}
	// The client sends its request line before it reads the answer: read
	// it first, so the answer and the close never race its write.
	if _, err := channel.ReadRequest(rw); err != nil {
		fmt.Fprintln(out, "The request could not be read.")
		out.exit(1)
		return
	}
	v, err := state.ReadOnly(h.Dir, h.Protectors.Resolve)
	switch {
	case errors.Is(err, state.ErrNotFound):
		fmt.Fprintln(out, "Not paired. An administrator pairs it with `vettid-agent pair --name <name>`, as the README says.")
		out.exit(0)
		return
	case err != nil:
		fmt.Fprintf(out, "The state file cannot be read: %v\n", err)
		out.exit(1)
		return
	}
	rec, err := pairing.DecodeRecord(v.State)
	clear(v.State)
	if err != nil {
		fmt.Fprintln(out, err)
		out.exit(1)
		return
	}
	writeStatus(out, h.Dir, v, rec, time.Now())
	clear(rec.Device)
	clear(rec.Leash)
	out.exit(0)
}

// pair answers `pair --name`: the request carries the code once.
// requestRead lifts the request's deadline once it is read: a pairing
// waits for the member's phone.
func (h *serviceHost) pair(ctx context.Context, rw io.ReadWriter, requestRead func()) {
	out := &consoleWriter{w: rw}
	req, err := channel.ReadRequest(rw)
	if err != nil {
		fmt.Fprintln(out, "The pairing request could not be read.")
		out.exit(1)
		return
	}
	requestRead()
	code := req.Code
	req.Code = ""
	o := pairing.Options{
		Store:         h.store,
		Resolve:       h.Protectors.Resolve,
		ResolveErr:    h.Protectors.ResolveErr,
		AllProtectors: protect.All(h.Dir),
		Protector:     h.Protectors.New,
		Code: func() (string, error) {
			c := code
			code = ""
			if c == "" {
				return "", errors.New("no pairing code was given")
			}
			return c, nil
		},
		CodeGiven: true,
		Restart:   req.Restart,
		Name:      req.Label,
		Out:       out,
	}
	if h.pairOptions != nil {
		h.pairOptions(&o)
	}
	err = pairing.Pair(ctx, o)
	code = ""
	if err != nil {
		fmt.Fprintln(out, err)
		out.exit(1)
		return
	}
	out.exit(0)
}

// forget answers `forget --name`: the state's keys and files are
// deleted, through every protector that could hold its key.
func (h *serviceHost) forget(rw io.ReadWriter) {
	out := &consoleWriter{w: rw}
	if _, err := channel.ReadRequest(rw); err != nil {
		fmt.Fprintln(out, "The request could not be read.")
		out.exit(1)
		return
	}
	err := h.store.Wipe(h.Protectors.Resolve)
	switch {
	case errors.Is(err, state.ErrNothingToWipe):
		fmt.Fprintln(out, "Nothing to forget: this connector holds no pairing.")
		out.exit(0)
	case errors.Is(err, state.ErrProtectorUnknown):
		// Wipe removed the files but knew no protector: ask every one.
		if err := h.store.WipeAll(protect.All(h.Dir)); err != nil {
			fmt.Fprintf(out, "The pairing's files are removed, but a key may remain: %v\n", err)
			out.exit(1)
			return
		}
		fmt.Fprintln(out, "Forgotten: this connector's keys and state are deleted. Remove the agent on your phone too.")
		out.exit(0)
	case err != nil:
		fmt.Fprintf(out, "The pairing could not be forgotten, and is kept so that forget can be tried again: %v\n", err)
		out.exit(1)
	default:
		fmt.Fprintln(out, "Forgotten: this connector's keys and state are deleted. Remove the agent on your phone too.")
		out.exit(0)
	}
}

// consoleWriter sends what is written to it as the console exchange's
// text lines (channel.WriteText), one per line; exit flushes a last
// partial line and sends the exit code.
type consoleWriter struct {
	w   io.Writer
	buf []byte
	err error
}

func (c *consoleWriter) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	c.buf = append(c.buf, p...)
	for {
		i := bytes.IndexByte(c.buf, '\n')
		if i < 0 {
			break
		}
		if c.err = channel.WriteText(c.w, string(c.buf[:i])); c.err != nil {
			return 0, c.err
		}
		c.buf = c.buf[i+1:]
	}
	return len(p), nil
}

func (c *consoleWriter) exit(code int) {
	if len(c.buf) > 0 && c.err == nil {
		c.err = channel.WriteText(c.w, string(c.buf))
		c.buf = nil
	}
	if c.err == nil {
		_ = channel.WriteExit(c.w, code)
	}
}
