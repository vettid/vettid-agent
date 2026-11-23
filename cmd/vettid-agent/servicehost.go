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

// hostConn is one admitted client of the channel.
type hostConn struct {
	rw     io.ReadWriter
	op     channel.Op
	accept func() error          // the operation may start
	refuse func(err error) error // refused, and closed
	close  func() error
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

	mu        sync.Mutex
	mcpActive bool // a stub's session runs
	exclusive bool // pair or forget runs
	holds     int  // clients being served, and what else holds the host
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

// Serve opens the state directory and serves the clients accept returns
// until ctx ends (it then returns ctx's error), accept fails (its error),
// or nothing has held the host for IdleStop (errIdle). Every client's
// operation has ended when it returns, and the state directory is
// closed.
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
	defer cancel(nil)
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := accept(ctx)
			if err != nil {
				if ctx.Err() == nil {
					cancel(err)
				}
				return
			}
			h.Hold()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer h.Release()
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
			if h.Held() == 0 {
				cancel(errIdle)
				return errIdle
			}
		}
	}
}

// handle runs one client's operation and closes it.
func (h *serviceHost) handle(ctx context.Context, c *hostConn) {
	switch c.op {
	case channel.OpMCP:
		if !h.claim(&h.mcpActive) {
			_ = c.refuse(channel.ErrInUse)
			return
		}
		defer h.unclaim(&h.mcpActive)
		defer c.close()
		if c.accept() != nil {
			return
		}
		h.runSession(ctx, c.rw)
	case channel.OpStatus:
		defer c.close()
		if c.accept() != nil {
			return
		}
		h.status(c.rw)
	case channel.OpPair, channel.OpForget:
		if !h.claim(&h.exclusive) {
			_ = c.refuse(channel.ErrInUse)
			return
		}
		defer h.unclaim(&h.exclusive)
		defer c.close()
		if c.accept() != nil {
			return
		}
		if c.op == channel.OpPair {
			h.pair(ctx, c.rw)
		} else {
			h.forget(c.rw)
		}
	default:
		_ = c.refuse(channel.ErrNotAllowed)
	}
}

// claim sets *flag if neither a session nor pair or forget runs: one
// stub at a time, and pair and forget only while no stub is served.
func (h *serviceHost) claim(flag *bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mcpActive || h.exclusive {
		return false
	}
	*flag = true
	return true
}

func (h *serviceHost) unclaim(flag *bool) {
	h.mu.Lock()
	*flag = false
	h.mu.Unlock()
}

// runSession serves one stub: the paired record's MCP session over rw,
// or, with no finished pairing, every tool answered not_paired.
func (h *serviceHost) runSession(ctx context.Context, rw io.ReadWriter) {
	logger := h.Log
	rec, err := h.loadRecord()
	if err != nil {
		logger.Warn("no MCP session", "err", err)
		srv := mcp.New(mcp.Options{Unavailable: &request.Error{Code: codeNotPaired, Text: textNotPaired}, Version: readVersion().Version, Log: logger})
		_ = srv.Serve(ctx, rw, rw)
		return
	}
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

// loadRecord reads the finished pairing.
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
		return nil, vaultconn.ErrNotPaired
	}
	return rec, nil
}

// status answers `status --name`: what status shows for a state
// directory, read without the vault.
func (h *serviceHost) status(rw io.ReadWriter) {
	out := &consoleWriter{w: rw}
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
	out.exit(0)
}

// pair answers `pair --name`: the request carries the code once.
func (h *serviceHost) pair(ctx context.Context, rw io.ReadWriter) {
	out := &consoleWriter{w: rw}
	req, err := channel.ReadRequest(rw)
	if err != nil {
		fmt.Fprintln(out, "The pairing request could not be read.")
		out.exit(1)
		return
	}
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
