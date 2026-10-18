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
	// OnEvent, if set, receives every event (a message without `re`) of
	// a batch after the batch was saved, in Run's goroutine; it must not
	// block or call back into Conn synchronously.
	OnEvent func(Event)
	// StatusEvery is how often Run sends vault.status (also at start and
	// after a failed save); default 6 hours.
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
	// lastBatchEmpty: the last Poll brought no response or event.
	lastBatchEmpty bool
	refreshAt      time.Time
	statusID       string
	ownerCheck     string
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
	return c, nil
}

// persist is the client's Config.Persist: called inside Poll after a
// batch was handled and before it is acknowledged. It takes the batch's
// responses and events (they are dispatched after Poll returns); on
// device.unlinked it wipes the state instead of saving it; otherwise it
// writes the record durably. An error leaves the batch unacknowledged.
func (c *Conn) persist(st []byte) error {
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
	rec := pairing.Record{Phase: pairing.PhasePaired, Device: bytes.Clone(st)}
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
	return nil
}

// Run owns the device until ctx ends, device.unlinked arrives
// (ErrUnlinked, after the wipe) or the relay refuses this agent
// (ErrRefused, nothing wiped). It sends vault.status at start, every
// StatusEvery and after a failed save, so that what the vault holds is
// read again rather than inferred from events that may have been lost
// (an event is acknowledged once saved, and handed over only after).
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
		perr := c.dev.Poll(ctx)
		c.dispatch()
		if c.unlinked {
			if c.wipeErr != nil {
				return fmt.Errorf("%w\nBut its keys could not be deleted from this computer (%v); delete the state directory yourself", errors.New("This agent was removed from your vault."), c.wipeErr)
			}
			fmt.Fprintln(c.o.Out, TextUnlinked)
			return ErrUnlinked
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case c.persistErr != nil:
			c.log.Warn("state not saved; the batch stays unacknowledged", "err", c.persistErr)
			c.persistErr = nil
			c.refreshAt = c.o.Now() // read what the vault holds again
			pause(ctx, time.Second)
		case perr != nil:
			c.log.Warn("collect failed", "err", errCode(perr))
			pause(ctx, time.Second)
		}
		if c.refused {
			// Keep collecting while device.unlinked may still be
			// waiting (VAULT-MESSAGING §8.6); stop once a collect
			// brings nothing.
			if perr == nil && c.lastBatchEmpty {
				fmt.Fprintln(c.o.Out, TextRefused)
				return ErrRefused
			}
		}
	}
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
func (c *Conn) sendStatus(ctx context.Context) {
	c.refreshAt = c.o.Now().Add(c.o.StatusEvery)
	id, err := c.dev.Send(ctx, "vault.status", json.RawMessage(`{}`))
	if err != nil {
		c.sendFailed(err)
		return
	}
	c.statusID = id
	c.log.Info("sent", "type", "vault.status", "id", id)
}

// sendFailed records a failed deposit to the vault's mailbox.
func (c *Conn) sendFailed(err error) {
	c.log.Warn("send failed", "err", errCode(err))
	if relayclient.IsCode(err, "token_revoked") {
		c.refused = true
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
	c.lastBatchEmpty = len(evs) == 0
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
