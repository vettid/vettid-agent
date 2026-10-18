// Package vaultconn is the connector's use of the vault client
// (AGENT-PLAN §3.1, §3.3, §6 A2.2): it owns the client.Device in one
// goroutine (Run), collects the device's mailbox by long poll, saves the
// state before a collected batch is acknowledged (the client's
// Config.Persist, AGENT-PLAN §7.1 AV1), dispatches responses to waiting
// requests by `re`, and handles device.unlinked and a refused relay key
// (AG12). Token upkeep, rekeys and identity rotation are done by the
// client while it handles messages, and saved with the batch.
//
// Only Run's goroutine calls the client (AGENT-PLAN §3.2: until the
// client has one collecting loop of its own, AV2). Other goroutines
// reach the vault through Request.
//
// Logs carry message types, ids and error codes, never bodies or keys.
package vaultconn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/envelope"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
)

// Operator texts (AGENT-PLAN §11).
const (
	// TextUnlinked is shown after the state was wiped on device.unlinked.
	TextUnlinked = "This agent was removed from your vault. Its keys have been deleted from this computer."
	// TextRefused is shown when the relay refuses this agent's key
	// (token_revoked) and no device.unlinked arrived.
	TextRefused = "Your vault's relay refused this agent. If you removed it on your phone, run `vettid-agent forget`."
)

var (
	// ErrUnlinked: device.unlinked arrived; the state was wiped (unless
	// the error also says the wipe failed).
	ErrUnlinked = errors.New(TextUnlinked)
	// ErrRefused: the relay refused a deposit to the vault's mailbox with
	// token_revoked; nothing was wiped (VAULT-MESSAGING §8.6).
	ErrRefused = errors.New(TextRefused)
	// ErrStopped: Request after Run ended.
	ErrStopped = errors.New("the connection to the vault has stopped")
	// ErrNotPaired: the record is not a completed pairing.
	ErrNotPaired = errors.New("this connector is not paired: run `vettid-agent pair`")
)

// Store is what vaultconn uses of *state.Store (opened, locked and
// loaded by the caller, so that Save writes under the loaded data key).
type Store interface {
	Save([]byte) error
	Wipe(state.Resolver) error
}

// Options configure New.
type Options struct {
	Store   Store
	Resolve state.Resolver
	// Record is the loaded state file's record; it must be paired.
	Record *pairing.Record
	// Out is the operator's terminal (standard error): the AG12 texts.
	Out io.Writer
	// Log is for diagnostics (types, ids, codes); nil discards.
	Log *slog.Logger
	// OnEvent, if set, receives the events (messages without `re`) of a
	// batch after Poll returns, in Run's goroutine; it must not block or
	// call back into Conn synchronously. An event is delivered even when
	// its batch could not be saved (the batch is then collected again but
	// recognised as handled, so not delivered twice in this process), and
	// after a crash between the save and the acknowledgement it may be
	// delivered again by the next process... or, if the crash came after
	// the acknowledgement, not at all. Handlers must therefore be
	// idempotent and must not rely on seeing every event: the state they
	// depend on is read again from the vault at start. device.unlinked is
	// not passed on (vaultconn acts on it itself).
	OnEvent func(Event)
	// OnStatus, if set, receives the owner check state ("ok", "due",
	// "held") of every vault.status response, in Run's goroutine.
	OnStatus func(ownerCheck string)
	// StatusEvery is how often Run sends vault.status after the one at
	// start; default 6 hours.
	StatusEvery time.Duration

	// HTTP, Now and PollWait go to the client (nil and zero: its
	// defaults; PollWait bounds how long a Request waits before it is
	// sent).
	HTTP     *http.Client
	Now      func() time.Time
	PollWait time.Duration
}

// Event is a vault message that is not a response.
type Event struct {
	ID   string
	Type string
	Body json.RawMessage
}

// Response is the vault's response to a Request.
type Response struct {
	Type      string
	OK        bool
	ErrorCode string
	Body      json.RawMessage
}

type result struct {
	resp *Response
	err  error
}

type call struct {
	typ  string
	body json.RawMessage
	done chan result // buffered, 1
	ctx  context.Context
}

// Conn is a running connection to the vault.
type Conn struct {
	o   Options
	dev *client.Device
	log *slog.Logger

	calls   chan *call
	stopped chan struct{}
	runErr  error

	// Run's goroutine only:
	pending    map[string]*call
	events     []*envelope.Inner // drained in persist, dispatched after Poll
	unlinked   bool
	wipeErr    error
	persistErr error
	refused    bool
	refusedAt  time.Time
	drains     int // collects since the refusal
	// collected: the last Poll collected at least one message (persist
	// ran), whether or not anything was handed over.
	collected bool
	// saveFails counts consecutive failed saves (an episode); retry is
	// the pause after the next failure.
	saveFails     int
	statusBackoff time.Duration
	refreshAt     time.Time
	statusID      string
	ownerCheck    string

	// The access session (VAULT-MESSAGING §6.8) as saved with each
	// batch. accMu guards it: Access and CompareAndSetAccess are called from other
	// goroutines.
	accMu  sync.Mutex
	access pairing.Access
}

// New restores the device from the record, with Persist writing the
// state through Store.
func New(o Options) (*Conn, error) {
	if o.Record == nil || o.Record.Phase != pairing.PhasePaired {
		return nil, ErrNotPaired
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.StatusEvery == 0 {
		o.StatusEvery = 6 * time.Hour
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	c := &Conn{o: o, log: o.Log, calls: make(chan *call), stopped: make(chan struct{}), pending: map[string]*call{}}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var st client.State
	if err := json.Unmarshal(o.Record.Device, &st); err != nil || st.Role != "agent" || st.DeviceID == "" || st.Vault == nil {
		return nil, ErrNotPaired
	}
	d, err := client.Load(client.Config{HTTP: o.HTTP, Now: o.Now, PollWait: o.PollWait, Persist: c.persist}, o.Record.Device)
	if err != nil {
		return nil, fmt.Errorf("the saved state could not be restored: %w", err)
	}
	c.dev = d
	c.access = o.Record.Access
	return c, nil
}

// Access returns the access session as last known: from the record at
// start, then from device.session.granted and .ended (applied in the
// save of the batch that carried them), and CompareAndSetAccess.
func (c *Conn) Access() pairing.Access {
	c.accMu.Lock()
	defer c.accMu.Unlock()
	return c.access
}

// CompareAndSetAccess replaces the access session with a only if it is
// still old, atomically, and reports whether it did. internal/access
// uses it for what it learns from a probe or a session_required answer,
// with old the session as it was when the request was sent: a batch
// that changed the session in between (a grant or an end) is never
// overwritten. The result is saved with the next batch. An invalid a is
// refused.
func (c *Conn) CompareAndSetAccess(old, a pairing.Access) bool {
	if !a.Valid() {
		return false
	}
	c.accMu.Lock()
	defer c.accMu.Unlock()
	if c.access != old {
		return false
	}
	c.access = a
	return true
}

// applyAccess applies a batch's device.session.granted and .ended to the
// access session, in order. Idempotent: applying the same events again
// gives the same result. A granted whose body is malformed is ignored
// (logged).
func (c *Conn) applyAccess(evs []*envelope.Inner) {
	c.accMu.Lock()
	defer c.accMu.Unlock()
	for _, ev := range evs {
		if ev.Re != "" {
			continue
		}
		switch ev.Type {
		case "device.session.granted":
			a, ok := ParseGranted(ev.Body)
			if !ok {
				c.log.Warn("malformed event", "type", ev.Type, "id", ev.ID)
				continue
			}
			c.access = a
		case "device.session.ended":
			c.access = pairing.Access{State: pairing.AccessNone}
		}
	}
}

// ParseGranted reads device.session.granted{session_id, expires_at}
// (VAULT-MESSAGING §10.3).
func ParseGranted(body json.RawMessage) (pairing.Access, bool) {
	var g struct {
		SessionID string `json:"session_id"`
		ExpiresAt string `json:"expires_at"`
	}
	if json.Unmarshal(body, &g) != nil || g.SessionID == "" {
		return pairing.Access{}, false
	}
	exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil {
		return pairing.Access{}, false
	}
	a := pairing.Access{State: pairing.AccessActive, SessionID: g.SessionID, ExpiresAt: exp}
	return a, a.Valid()
}

// persist is the client's Config.Persist: called inside Poll after a
// batch was handled and before it is acknowledged. It takes the batch's
// responses and events (they are dispatched after Poll returns); on
// device.unlinked it wipes the state instead of saving it; otherwise it
// writes the record durably. An error leaves the batch unacknowledged.
func (c *Conn) persist(st []byte) error {
	c.collected = true
	evs := c.dev.Events()
	c.events = append(c.events, evs...)
	for _, ev := range evs {
		if ev.Re == "" && ev.Type == "device.unlinked" {
			c.unlinked = true
		}
	}
	if c.unlinked {
		// AG12: wipe first; the operator is told after Run sees it.
		if err := c.o.Store.Wipe(c.o.Resolve); err != nil && !errors.Is(err, state.ErrNothingToWipe) {
			c.wipeErr = err
			return err
		}
		c.wipeErr = nil
		return nil
	}
	// The batch's access events are applied before the save, so they are
	// in the state file before the relay drops them.
	c.applyAccess(evs)
	rec := pairing.Record{Phase: pairing.PhasePaired, Device: bytes.Clone(st), Access: c.Access()}
	b, err := rec.Encode()
	clear(rec.Device)
	if err != nil {
		c.persistErr = err
		return err
	}
	err = c.o.Store.Save(b)
	clear(b)
	if err != nil {
		// Also ErrNotDurable: the batch is collected again and saved
		// again.
		c.persistErr = err
		return err
	}
	if c.saveFails > 0 {
		c.log.Warn("state saved again", "after_failures", c.saveFails)
		c.saveFails = 0
	}
	return nil
}

// Pauses after failures; tests shorten them.
var (
	retryBase       = time.Second
	retryMax        = 30 * time.Second
	statusRetryMax  = 5 * time.Minute
	drainMaxCollect = 5
	drainMaxTime    = time.Minute
)

// Run owns the device until ctx ends, device.unlinked arrives
// (ErrUnlinked, after the wipe) or the relay refuses this agent
// (ErrRefused, nothing wiped). It sends vault.status at start (retried
// with a growing pause until it is sent) and every StatusEvery, so that
// what the vault holds is read again at start rather than inferred from
// events a crash may have lost (an event is acknowledged once saved, and
// handed over only after). A save that fails is retried with a pause
// growing from retryBase to retryMax; only the first failure of an
// episode and the recovery are logged.
func (c *Conn) Run(ctx context.Context) (err error) {
	defer func() {
		c.runErr = err
		for id, cl := range c.pending {
			cl.done <- result{err: ErrStopped}
			delete(c.pending, id)
		}
		close(c.stopped)
	}()
	c.refreshAt = c.o.Now()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !c.refused && !c.o.Now().Before(c.refreshAt) {
			c.sendStatus(ctx)
		}
		c.takeCalls(ctx)
		c.collected = false
		perr := c.dev.Poll(ctx)
		c.dispatch()
		if c.unlinked {
			if c.wipeErr != nil {
				// The batch stays unacknowledged, so device.unlinked is
				// collected again by the next run. The protectors in
				// this build keep no key outside the state file (the
				// TPM's sealed object and the DPAPI blob live in it; a
				// passphrase has none), so deleting the directory
				// removes everything.
				return &wipeFailed{c.wipeErr}
			}
			fmt.Fprintln(c.o.Out, TextUnlinked)
			return ErrUnlinked
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case c.persistErr != nil:
			// No vault.status here: it would add a response to the
			// unacknowledged mailbox on every retry; the one at start
			// covers a crash.
			if c.saveFails == 0 {
				c.log.Warn("state not saved; the batch stays unacknowledged and is retried", "err", c.persistErr)
			}
			c.saveFails++
			c.persistErr = nil
			pause(ctx, backoff(retryBase, retryMax, c.saveFails))
		case perr != nil:
			c.log.Warn("collect failed", "err", errCode(perr))
			pause(ctx, retryBase)
		}
		if c.refused {
			// Keep collecting while device.unlinked may still be
			// waiting (VAULT-MESSAGING §8.6): until a collect brings
			// nothing, but at most drainMaxCollect collects or
			// drainMaxTime, even if collects or saves keep failing.
			c.drains++
			empty := perr == nil && !c.collected
			if empty || c.drains >= drainMaxCollect || c.o.Now().Sub(c.refusedAt) >= drainMaxTime {
				fmt.Fprintln(c.o.Out, TextRefused)
				return ErrRefused
			}
		}
	}
}

// wipeFailed: device.unlinked arrived but the wipe failed.
type wipeFailed struct{ err error }

func (e *wipeFailed) Error() string {
	return fmt.Sprintf("This agent was removed from your vault, but its keys could not be deleted from this computer (%v). Run `vettid-agent mcp` again to retry, or delete the state directory (the protectors of this version keep no key outside it).", e.err)
}
func (e *wipeFailed) Unwrap() error { return e.err }

// backoff returns base doubled n-1 times, at most max.
func backoff(base, max time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < max; i++ {
		d *= 2
	}
	return min(d, max)
}

// pause waits d or until ctx ends.
func pause(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// sendStatus sends vault.status; its response is read in dispatch.
// A failed send is retried after a pause growing from retryBase to
// statusRetryMax; only a sent request schedules the next one at
// StatusEvery.
func (c *Conn) sendStatus(ctx context.Context) {
	id, err := c.dev.Send(ctx, "vault.status", json.RawMessage(`{}`))
	if err != nil {
		c.sendFailed(err)
		if c.statusBackoff == 0 {
			c.statusBackoff = retryBase
		} else {
			c.statusBackoff = min(2*c.statusBackoff, statusRetryMax)
		}
		c.refreshAt = c.o.Now().Add(c.statusBackoff)
		return
	}
	c.statusBackoff = 0
	c.refreshAt = c.o.Now().Add(c.o.StatusEvery)
	c.statusID = id
	c.log.Info("sent", "type", "vault.status", "id", id)
}

// sendFailed records a failed deposit to the vault's mailbox.
func (c *Conn) sendFailed(err error) {
	c.log.Warn("send failed", "err", errCode(err))
	if relayclient.IsCode(err, "token_revoked") && !c.refused {
		c.refused, c.refusedAt = true, c.o.Now()
		c.failPending(ErrRefused)
	}
}

func (c *Conn) failPending(err error) {
	for id, cl := range c.pending {
		cl.done <- result{err: err}
		delete(c.pending, id)
	}
}

// takeCalls sends the requests waiting for Run's goroutine.
func (c *Conn) takeCalls(ctx context.Context) {
	for {
		select {
		case cl := <-c.calls:
			if cl.ctx.Err() != nil {
				cl.done <- result{err: cl.ctx.Err()}
				continue
			}
			if c.refused {
				cl.done <- result{err: ErrRefused}
				continue
			}
			id, err := c.dev.Send(ctx, cl.typ, cl.body)
			if err != nil {
				c.sendFailed(err)
				if c.refused {
					cl.done <- result{err: ErrRefused}
				} else {
					cl.done <- result{err: fmt.Errorf("could not send %s to the vault: %s", cl.typ, errCode(err))}
				}
				continue
			}
			c.log.Info("sent", "type", cl.typ, "id", id)
			c.pending[id] = cl
		default:
			return
		}
	}
}

// dispatch hands the batch's responses to their requests by `re` and
// its events to OnEvent.
func (c *Conn) dispatch() {
	evs := c.events
	c.events = nil
	for id, cl := range c.pending {
		if cl.ctx.Err() != nil {
			delete(c.pending, id)
		}
	}
	for _, in := range evs {
		if in.Re != "" {
			resp := &Response{Type: in.Type, OK: in.Status == envelope.StatusOK, Body: in.Body}
			if in.Error != nil {
				resp.ErrorCode = in.Error.Code
			}
			c.log.Info("response", "type", in.Type, "re", in.Re, "ok", resp.OK, "code", resp.ErrorCode)
			if in.Re == c.statusID {
				c.statusID = ""
				c.readStatus(resp)
				continue
			}
			if cl, ok := c.pending[in.Re]; ok {
				delete(c.pending, in.Re)
				cl.done <- result{resp: resp}
			}
			continue
		}
		c.log.Info("event", "type", in.Type, "id", in.ID)
		if in.Type == "device.unlinked" {
			continue // acted on in persist
		}
		if c.o.OnEvent != nil {
			c.o.OnEvent(Event{ID: in.ID, Type: in.Type, Body: in.Body})
		}
	}
}

// readStatus keeps what vault.status says about the owner check.
func (c *Conn) readStatus(r *Response) {
	if !r.OK {
		return
	}
	var s struct {
		OwnerCheck struct {
			State string `json:"state"`
		} `json:"owner_check"`
	}
	if json.Unmarshal(r.Body, &s) == nil {
		c.ownerCheck = s.OwnerCheck.State
		if c.o.OnStatus != nil && s.OwnerCheck.State != "" {
			c.o.OnStatus(s.OwnerCheck.State)
		}
	}
}

// Request sends a request to the vault through Run's goroutine and
// waits for its response, ctx's end or Run's end.
func (c *Conn) Request(ctx context.Context, typ string, body json.RawMessage) (*Response, error) {
	cl := &call{typ: typ, body: body, done: make(chan result, 1), ctx: ctx}
	select {
	case c.calls <- cl:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.stopped:
		return nil, ErrStopped
	}
	select {
	case r := <-cl.done:
		return r.resp, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.stopped:
		select {
		case r := <-cl.done:
			return r.resp, r.err
		default:
			return nil, ErrStopped
		}
	}
}

// errCode returns a relay error's status and code, or a fixed text:
// never a body.
func errCode(err error) string {
	var re *relayclient.Error
	if errors.As(err, &re) {
		return fmt.Sprintf("relay HTTP %d %s", re.Status, sanitizeCode(re.Code))
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	if errors.Is(err, client.ErrNotPaired) {
		return "not paired"
	}
	return "transport error"
}

// sanitizeCode keeps a relay error code printable and short.
func sanitizeCode(s string) string {
	b := make([]byte, 0, 64)
	for i := 0; i < len(s) && len(b) < 64; i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' {
			b = append(b, ch)
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}
