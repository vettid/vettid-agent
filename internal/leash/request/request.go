// Package request makes the agent's LEASH requests to the vault
// (AGENT-PLAN §2 AG5, AG9, §4.1, §4.4, §6 A3.2; VAULT-MESSAGING §6.8,
// §8.1, §8.2, §8.6, §10.11): agent.request with op `catalog`,
// `item.get` and `item.use`, for the MCP tools of A3.3
// (leash.list_available, leash.request_secret, leash.execute_action and
// leash.check_status).
//
// A request runs in a goroutine of its own. The tool call that made it
// waits up to Options.Wait (AG9: 20 s) and then returns a pending
// outcome with the request's id, while the goroutine keeps waiting for
// the vault: up to Options.Attempt for an answer, or, once the vault
// said with approval.waiting that it holds the request for the member's
// approval, until that approval's `exp` plus Options.Grace (§4.4). A
// request that got no answer by then is sent again under the same inner
// id, at most twice (§8.6), so that the vault answers it from its
// dedupe (§8.2) and never executes it twice. Any answer is final: a
// request answered `forbidden`, `denied` or `approval_timeout` (or any
// other code) is never sent again (AGENT-PLAN §4.1, §4.7).
//
// Results are kept in memory only, for Options.Keep (AG9: 10 minutes)
// after the answer, and returned once: a result handed to a caller is
// no longer kept here. Nothing of a request is written to the state
// file. Item values are kept as their JSON text in byte slices that
// Result.Wipe zeroes; the vault's response body is zeroed once it is
// parsed, and a result that is not collected is zeroed when it is
// dropped. Logs carry the op, the request id and the error code, never
// a body, an item value or a name.
package request

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// The ops of agent.request (VAULT-MESSAGING §10.11).
const (
	OpCatalog = "catalog"
	OpGet     = "item.get"
	OpUse     = "item.use"
)

// Bounds of agent.request (VAULT-MESSAGING §10.11; VAULT-ITEMS limits
// as the vault checks them).
const (
	MaxFields  = 64
	MaxUseData = 16384
	// Retransmissions: an application retry reuses the inner id, at
	// most twice (VAULT-MESSAGING §8.6).
	Retransmissions = 2
	// ApprovalTTL is how long the vault holds a request (§6.8); an
	// approval.waiting `exp` further ahead than this (plus a minute of
	// clock skew) is read as this.
	ApprovalTTL = 5 * time.Minute
)

// Defaults of Options.
const (
	DefaultWait       = 20 * time.Second // AG9
	DefaultAttempt    = access.RequestTimeout
	DefaultGrace      = 30 * time.Second // AGENT-PLAN §4.4
	DefaultUnanswered = 30 * time.Second // AGENT-PLAN §4.4: a locked vault
	DefaultKeep       = 10 * time.Minute // AG9
	DefaultRetryPause = 2 * time.Second
	DefaultMaxPending = 32
)

// Texts (AGENT-PLAN §11 where it drafts one; the others are chosen).
const (
	TextWaiting   = "Waiting for your approval on your phone. Check again with leash.check_status."
	TextInFlight  = "Your vault has not answered yet. Check again with leash.check_status."
	TextDenied    = "Declined on your phone."
	TextForbidden = "Your vault does not allow this agent to do that. You can change its permissions on your phone."
	TextSuspended = "Your vault paused this agent after repeated refused requests. You can resume it on your phone."
	TextTimeout   = "Your phone did not answer in time, and the request was dropped. Make it again if you still need it."
	TextExpired   = "No result is kept for this request: a result is returned once and kept at most 10 minutes, and none survives a restart of the connector. Make the request again."
	TextSession   = "Your access session ended before your vault ran this request. Try again."
	TextNotFound  = "That item has no such field, or the field cannot be used this way."
	TextLimit     = "Too many requests are waiting for approval on your phone. Try again after you answer them."
	TextTooMany   = "Too many requests are waiting for your vault. Check their status, or try again later."
	TextProtocol  = "Your vault's answer could not be read."
	TextStopped   = "The connection to your vault has stopped."
)

// Error is a request's outcome other than a result, with a stable code
// (AGENT-PLAN §4.1: the vault's error code, or the connector's own).
type Error struct {
	Code string
	Text string
	// RequestID is set when the request is still in flight (the vault
	// has not answered yet, AGENT-PLAN §4.4): check it again later.
	RequestID string
	// Until, from internal/access: when a new access request may be sent.
	Until time.Time
}

func (e *Error) Error() string { return e.Text }

// Is matches by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Sentinels for errors.Is.
var (
	ErrDenied      = &Error{Code: "denied", Text: TextDenied}
	ErrForbidden   = &Error{Code: "forbidden", Text: TextForbidden}
	ErrSuspended   = &Error{Code: "suspended", Text: TextSuspended}
	ErrTimeout     = &Error{Code: "approval_timeout", Text: TextTimeout}
	ErrExpired     = &Error{Code: "expired", Text: TextExpired}
	ErrOwnerCheck  = &Error{Code: access.ErrOwnerCheck.Code, Text: access.ErrOwnerCheck.Text}
	ErrUnreachable = &Error{Code: access.ErrUnreachable.Code, Text: access.ErrUnreachable.Text}
	ErrSession     = &Error{Code: "session_required", Text: TextSession}
	ErrNotFound    = &Error{Code: "not_found", Text: TextNotFound}
	ErrLimit       = &Error{Code: "limit", Text: TextLimit}
	ErrTooMany     = &Error{Code: "rate_limited_local", Text: TextTooMany}
	ErrProtocol    = &Error{Code: "protocol_error", Text: TextProtocol}
	ErrStopped     = &Error{Code: "vault_unreachable", Text: TextStopped}
	ErrRefused     = &Error{Code: "refused", Text: vaultconn.TextRefused}
)

// Conn is what this package uses of *vaultconn.Conn.
type Conn interface {
	NewID() (string, error)
	RequestWithID(ctx context.Context, id, typ string, body json.RawMessage) (*vaultconn.Response, error)
}

// Access is what this package uses of *access.Manager.
type Access interface {
	Ensure(ctx context.Context) error
	Snapshot() pairing.Access
	OnAnswer(code string, sentWith pairing.Access)
}

// Options configure New. Zero durations take the defaults.
type Options struct {
	// Log is for diagnostics (op, request id, codes); nil discards.
	Log *slog.Logger
	// Suspended, if set, reports whether the vault suspended this agent
	// (internal/leash, from leash.grant.updated): then nothing is sent,
	// and a `forbidden` answer is reported as the suspension.
	Suspended func() bool

	Wait       time.Duration // a tool call's wait before it returns pending
	Attempt    time.Duration // the wait for an answer before a retransmission
	Grace      time.Duration // the wait past a held request's exp
	Unanswered time.Duration // after this without any answer, Status says vault_unreachable
	Keep       time.Duration // how long an uncollected result or error is kept
	RetryPause time.Duration // the pause after a send that failed
	MaxPending int           // requests in flight and results kept, at once
}

// Label is a field's metadata in the catalog.
type Label struct {
	FieldID string `json:"field_id"`
	Label   string `json:"label"`
	Kind    string `json:"kind"`
}

// CatalogItem is an item the agent's grants include: metadata only.
type CatalogItem struct {
	ItemID   string  `json:"item_id"`
	Name     string  `json:"name"`
	Category string  `json:"category"`
	Labels   []Label `json:"labels"`
}

// Field is an item field with its value. Value is the value's JSON text
// as the vault sent it (a string, or an address object), absent for a
// field without a stored value.
type Field struct {
	FieldID string          `json:"field_id"`
	Label   string          `json:"label"`
	Kind    string          `json:"kind"`
	Value   json.RawMessage `json:"value,omitempty"`
}

// Item is item.get's answer. Notes is the notes' JSON text (a string),
// absent when the vault sent none.
type Item struct {
	ItemID   string          `json:"item_id"`
	Name     string          `json:"name"`
	Category string          `json:"category"`
	Fields   []Field         `json:"fields"`
	Notes    json.RawMessage `json:"notes,omitempty"`
}

// Use is item.use's answer: HMAC-SHA-256 keyed with the field's value.
type Use struct {
	ItemID  string
	FieldID string
	Action  string
	Result  []byte // 32 bytes
}

// Result is an answered request. Exactly one of Catalog (for catalog,
// possibly empty), Item and Use is set, by Op.
type Result struct {
	Op      string
	Catalog []CatalogItem
	Item    *Item
	Use     *Use
}

// Wipe zeroes the item's values and notes and the HMAC. The caller that
// receives a Result owns it and calls Wipe once it has used it.
func (r *Result) Wipe() {
	if r == nil {
		return
	}
	if r.Item != nil {
		for i := range r.Item.Fields {
			clear(r.Item.Fields[i].Value)
		}
		clear(r.Item.Notes)
	}
	if r.Use != nil {
		clear(r.Use.Result)
	}
}

// Outcome is what a request or Status returns when it is not an error:
// a Result, or pending with the request's id.
type Outcome struct {
	Result *Result
	// Pending: no answer yet; check again with Status(RequestID).
	Pending   bool
	RequestID string
	// Waiting: the vault holds the request for the member's approval.
	Waiting bool
	Text    string
}

// Client makes agent.request requests. It is safe for concurrent use.
type Client struct {
	conn Conn
	acc  Access
	o    Options
	log  *slog.Logger
	life context.Context
	stop context.CancelFunc
	wg   sync.WaitGroup

	mu      sync.Mutex
	entries map[string]*entry
	closed  bool
}

// entry is one request; the fields after mu's comment are guarded by
// Client.mu.
type entry struct {
	id       string
	op       string
	itemID   string
	fieldID  string
	fields   []string
	body     json.RawMessage
	sentWith pairing.Access
	created  time.Time
	poke     chan struct{} // buffered 1: the deadline may have changed
	finished chan struct{} // closed when done

	// Client.mu:
	waiting    bool
	approvalID string
	exp        time.Time
	done       bool
	res        *Result
	err        *Error
	handed     bool // the tool call returned pending: kept for Status
	abandoned  bool // the tool call ended without the id: dropped when done
	evict      *time.Timer
}

// New returns a Client over the vault connection and the access
// manager. Close stops it.
func New(conn Conn, acc Access, o Options) *Client {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.Wait, DefaultWait)
	def(&o.Attempt, DefaultAttempt)
	def(&o.Grace, DefaultGrace)
	def(&o.Unanswered, DefaultUnanswered)
	def(&o.Keep, DefaultKeep)
	def(&o.RetryPause, DefaultRetryPause)
	if o.MaxPending <= 0 {
		o.MaxPending = DefaultMaxPending
	}
	c := &Client{conn: conn, acc: acc, o: o, log: o.Log, entries: map[string]*entry{}}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c.life, c.stop = context.WithCancel(context.Background())
	return c
}

// Close stops the requests' goroutines, waits for them, and zeroes and
// drops every kept result.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.stop()
	c.wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.entries {
		c.dropLocked(id, e)
	}
}

var fieldIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func badInput(what string) *Error {
	return &Error{Code: "bad_request", Text: "The request is not valid: " + what + "."}
}

// Catalog lists the items the agent's grants include
// (agent.request{op: "catalog"}; leash.list_available).
func (c *Client) Catalog(ctx context.Context) (*Outcome, error) {
	return c.do(ctx, &entry{op: OpCatalog, body: json.RawMessage(`{"op":"catalog"}`)})
}

// Get reads an item, or only the given fields (agent.request{op:
// "item.get"}; leash.request_secret).
func (c *Client) Get(ctx context.Context, itemID string, fields []string) (*Outcome, error) {
	if !envelope.ValidULID(itemID) {
		return nil, badInput("item_id is not an item id")
	}
	if fields != nil && (len(fields) == 0 || len(fields) > MaxFields) {
		return nil, badInput(fmt.Sprintf("fields must name 1 to %d fields", MaxFields))
	}
	seen := map[string]bool{}
	for _, f := range fields {
		if !fieldIDRE.MatchString(f) || seen[f] {
			return nil, badInput("fields must be distinct field ids")
		}
		seen[f] = true
	}
	m := map[string]any{"op": OpGet, "item_id": itemID}
	if fields != nil {
		m["fields"] = fields
	}
	body, _ := json.Marshal(m)
	return c.do(ctx, &entry{op: OpGet, itemID: itemID, fields: append([]string(nil), fields...), body: body})
}

// Use computes HMAC-SHA-256 keyed with a field's value over data,
// without the value leaving the vault (agent.request{op: "item.use"};
// leash.execute_action).
func (c *Client) Use(ctx context.Context, itemID, fieldID string, data []byte) (*Outcome, error) {
	if !envelope.ValidULID(itemID) {
		return nil, badInput("item_id is not an item id")
	}
	if !fieldIDRE.MatchString(fieldID) {
		return nil, badInput("field_id is not a field id")
	}
	if len(data) == 0 || len(data) > MaxUseData {
		return nil, badInput(fmt.Sprintf("data must be 1 to %d bytes", MaxUseData))
	}
	body, _ := json.Marshal(map[string]any{"op": OpUse, "item_id": itemID, "field_id": fieldID,
		"action": "hmac-sha256", "data": base64.StdEncoding.EncodeToString(data)})
	return c.do(ctx, &entry{op: OpUse, itemID: itemID, fieldID: fieldID, body: body})
}

// isClosed reports whether Close was called.
func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// do sends e's request and waits for its outcome up to Options.Wait in
// all (AG9's budget), access check included: internal/access may wait
// for the vault (a probe, a device.session.request), and is stopped at
// the budget's end with ErrUnreachable while its request goes on. A
// call whose ctx has ended, or after Close, sends nothing and asks the
// phone for nothing.
func (c *Client) do(ctx context.Context, e *entry) (*Outcome, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.isClosed() {
		return nil, ErrStopped
	}
	if c.o.Suspended != nil && c.o.Suspended() {
		return nil, ErrSuspended
	}
	budgetEnd := time.Now().Add(c.o.Wait)
	bctx, cancel := context.WithDeadline(ctx, budgetEnd)
	err := c.acc.Ensure(bctx)
	cancel()
	if cerr := ctx.Err(); cerr != nil {
		return nil, cerr
	}
	if err != nil {
		return nil, fromAccess(err)
	}
	id, err := c.conn.NewID()
	if err != nil {
		return nil, ErrStopped
	}
	e.id, e.created = id, time.Now()
	e.sentWith = c.acc.Snapshot()
	e.poke, e.finished = make(chan struct{}, 1), make(chan struct{})
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrStopped
	}
	if ctx.Err() != nil {
		c.mu.Unlock()
		return nil, ctx.Err()
	}
	if c.heldLocked() >= c.o.MaxPending {
		c.mu.Unlock()
		return nil, ErrTooMany
	}
	c.entries[id] = e
	c.wg.Add(1)
	c.mu.Unlock()
	c.log.Info("agent.request", "op", e.op, "id", id)
	go c.run(e)

	t := time.NewTimer(max(time.Until(budgetEnd), 0))
	defer t.Stop()
	select {
	case <-e.finished:
	case <-t.C:
	case <-ctx.Done():
	}
	c.mu.Lock()
	if e.done {
		res, rerr := c.takeLocked(e)
		c.mu.Unlock()
		return c.report(ctx, res, rerr, budgetEnd)
	}
	if ctx.Err() != nil {
		// The tool call ended before it got the id: nobody can collect
		// the result, so it is dropped when it arrives.
		e.abandoned = true
		c.mu.Unlock()
		return nil, ctx.Err()
	}
	e.handed = true
	out := pendingLocked(e)
	c.mu.Unlock()
	return out, nil
}

// Status returns a pending request's outcome (leash.check_status): still
// pending (Waiting when the vault holds it for approval), its result
// (once), or its error. After Options.Unanswered without any sign from
// the vault it answers ErrUnreachable with RequestID set (the request
// stays in flight, AGENT-PLAN §4.4). An id that is not known, whose
// result was already returned or dropped, gives ErrExpired.
func (c *Client) Status(ctx context.Context, requestID string) (*Outcome, error) {
	c.mu.Lock()
	e := c.entries[requestID]
	if e == nil || !e.handed {
		c.mu.Unlock()
		return nil, ErrExpired
	}
	if !e.done {
		if !e.waiting && time.Since(e.created) >= c.o.Unanswered {
			c.mu.Unlock()
			return nil, &Error{Code: ErrUnreachable.Code, Text: ErrUnreachable.Text, RequestID: requestID}
		}
		out := pendingLocked(e)
		c.mu.Unlock()
		return out, nil
	}
	if e.res != nil {
		res, _ := c.takeLocked(e)
		c.mu.Unlock()
		return c.report(ctx, res, nil, time.Now().Add(c.o.Wait))
	}
	rerr := e.err // errors are kept until evicted: they hold no secret
	c.mu.Unlock()
	return c.report(ctx, nil, rerr, time.Now().Add(c.o.Wait))
}

// heldLocked counts the requests in flight and the results kept (kept
// errors are small and do not count).
func (c *Client) heldLocked() int {
	n := 0
	for _, e := range c.entries {
		if !e.done || e.res != nil {
			n++
		}
	}
	return n
}

func pendingLocked(e *entry) *Outcome {
	o := &Outcome{Pending: true, RequestID: e.id, Waiting: e.waiting, Text: TextInFlight}
	if e.waiting {
		o.Text = TextWaiting
	}
	return o
}

// takeLocked removes a done entry and returns its outcome.
func (c *Client) takeLocked(e *entry) (*Result, *Error) {
	if e.evict != nil {
		e.evict.Stop()
	}
	delete(c.entries, e.id)
	res, err := e.res, e.err
	e.res = nil
	return res, err
}

// dropLocked removes an entry and zeroes its result.
func (c *Client) dropLocked(id string, e *entry) {
	if e.evict != nil {
		e.evict.Stop()
	}
	e.res.Wipe()
	e.res = nil
	delete(c.entries, id)
}

// report turns a final outcome into the tool's answer. A
// session_required answer asks for access now, in this tool call (AG8),
// until the call's budget ends at deadline: the access manager's answer
// is returned, or ErrSession if a session exists again.
func (c *Client) report(ctx context.Context, res *Result, err *Error, deadline time.Time) (*Outcome, error) {
	if err != nil {
		if err.Code == ErrSession.Code && ctx.Err() == nil && !c.isClosed() {
			bctx, cancel := context.WithDeadline(ctx, deadline)
			aerr := c.acc.Ensure(bctx)
			cancel()
			if aerr != nil {
				return nil, fromAccess(aerr)
			}
		}
		return nil, err
	}
	return &Outcome{Result: res}, nil
}

// fromAccess converts internal/access's errors.
func fromAccess(err error) *Error {
	var ae *access.Error
	switch {
	case errors.As(err, &ae):
		return &Error{Code: ae.Code, Text: ae.Text, Until: ae.Until}
	case errors.Is(err, vaultconn.ErrRefused):
		return ErrRefused
	default:
		return &Error{Code: "access_error", Text: err.Error()}
	}
}

// OnEvent takes the vault's events (vaultconn.Options.OnEvent; it must
// not block): approval.waiting{approval_id, request_id, exp} (§6.8)
// makes the request's goroutine wait until exp plus Options.Grace. It
// tolerates duplicates and reordering (§8.4): a repeated or older
// approval.waiting never shortens the wait, and one that arrives after
// the answer, or for a request not known, changes nothing.
func (c *Client) OnEvent(ev vaultconn.Event) {
	if ev.Type != "approval.waiting" {
		return
	}
	var b struct {
		ApprovalID string `json:"approval_id"`
		RequestID  string `json:"request_id"`
		Exp        string `json:"exp"`
	}
	if json.Unmarshal(ev.Body, &b) != nil || b.RequestID == "" {
		c.log.Warn("malformed event", "type", ev.Type, "id", ev.ID)
		return
	}
	now := time.Now()
	limit := now.Add(ApprovalTTL + time.Minute)
	exp, err := time.Parse(time.RFC3339Nano, b.Exp)
	if err != nil || exp.After(limit) {
		exp = now.Add(ApprovalTTL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[b.RequestID]
	if e == nil || e.done {
		return
	}
	if !e.waiting || exp.After(e.exp) {
		e.waiting, e.exp, e.approvalID = true, exp, b.ApprovalID
		c.log.Info("held for approval", "op", e.op, "id", e.id, "approval_id", b.ApprovalID)
	}
	select {
	case e.poke <- struct{}{}:
	default:
	}
}

var errAttemptTimeout = errors.New("no answer in time")

// run sends e's request, and again under the same inner id while no
// answer comes (at most Retransmissions times), and records the answer.
func (c *Client) run(e *entry) {
	defer c.wg.Done()
	for n := 0; n <= Retransmissions; n++ {
		if n > 0 {
			c.log.Info("agent.request sent again", "op", e.op, "id", e.id, "attempt", n+1)
		}
		resp, err := c.attempt(e)
		if err == nil && resp != nil {
			c.answer(e, resp)
			return
		}
		switch {
		case c.life.Err() != nil:
			c.finish(e, nil, ErrStopped)
			return
		case errors.Is(err, vaultconn.ErrRefused):
			c.finish(e, nil, ErrRefused)
			return
		case errors.Is(err, vaultconn.ErrStopped):
			c.finish(e, nil, ErrStopped)
			return
		case errors.Is(err, errAttemptTimeout):
		default:
			// The deposit failed (the relay was unreachable): the vault
			// has not seen this copy. Pause, then send it again.
			c.log.Warn("agent.request not sent", "op", e.op, "id", e.id)
			t := time.NewTimer(c.o.RetryPause)
			select {
			case <-t.C:
			case <-c.life.Done():
				t.Stop()
				c.finish(e, nil, ErrStopped)
				return
			}
		}
	}
	c.log.Warn("agent.request unanswered", "op", e.op, "id", e.id)
	c.finish(e, nil, ErrUnreachable)
}

// deadline is when the current attempt, started at start, stops
// waiting: Options.Attempt after it, or a held request's exp plus
// Options.Grace if later.
func (c *Client) deadline(e *entry, start time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := start.Add(c.o.Attempt)
	if e.waiting {
		if a := e.exp.Add(c.o.Grace); a.After(d) {
			d = a
		}
	}
	return d
}

// attempt sends one copy of e's request and waits for its answer until
// the deadline, which approval.waiting may move while it waits.
func (c *Client) attempt(e *entry) (*vaultconn.Response, error) {
	ctx, cancel := context.WithCancel(c.life)
	defer cancel()
	start := time.Now()
	timedOut := make(chan struct{})
	go func() {
		for {
			t := time.NewTimer(time.Until(c.deadline(e, start)))
			select {
			case <-t.C:
				if !time.Now().Before(c.deadline(e, start)) {
					close(timedOut)
					cancel()
					return
				}
			case <-e.poke:
				t.Stop()
			case <-ctx.Done():
				t.Stop()
				return
			}
		}
	}()
	resp, err := c.conn.RequestWithID(ctx, e.id, "agent.request", e.body)
	if err != nil {
		select {
		case <-timedOut:
			return nil, errAttemptTimeout
		default:
		}
		return nil, err
	}
	return resp, nil
}

// answer records the vault's answer; the response body is zeroed once
// it is parsed.
func (c *Client) answer(e *entry, resp *vaultconn.Response) {
	defer clear(resp.Body)
	if resp.OK {
		res, err := parse(e, resp.Body)
		if err != nil {
			c.log.Warn("agent.request answer not readable", "op", e.op, "id", e.id)
			c.finish(e, nil, ErrProtocol)
			return
		}
		c.log.Info("agent.request answered", "op", e.op, "id", e.id)
		c.finish(e, res, nil)
		return
	}
	code := resp.ErrorCode
	c.log.Info("agent.request refused", "op", e.op, "id", e.id, "code", code)
	switch code {
	case "session_required", "owner_check_required":
		c.acc.OnAnswer(code, e.sentWith)
	}
	var err *Error
	switch code {
	case "forbidden":
		err = ErrForbidden
		if c.o.Suspended != nil && c.o.Suspended() {
			err = ErrSuspended
		}
	case "denied":
		err = ErrDenied
	case "approval_timeout":
		err = ErrTimeout
	case "owner_check_required":
		err = ErrOwnerCheck
	case "session_required":
		err = ErrSession
	case "not_found":
		err = ErrNotFound
	case "limit":
		err = ErrLimit
	case "bad_request":
		err = badInput("your vault refused it")
	default:
		sc := sanitize(code)
		err = &Error{Code: sc, Text: "Your vault refused the request (" + sc + ")."}
	}
	c.finish(e, nil, err)
}

// finish records e's final outcome.
func (c *Client) finish(e *entry, res *Result, err *Error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(e.body)
	e.done, e.res, e.err = true, res, err
	close(e.finished)
	switch {
	case e.abandoned || c.closed:
		c.dropLocked(e.id, e)
	case e.handed:
		c.scheduleLocked(e)
	}
	// Otherwise the tool call that made it is about to take it.
}

// scheduleLocked drops e Options.Keep after now.
func (c *Client) scheduleLocked(e *entry) {
	e.evict = time.AfterFunc(c.o.Keep, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.entries[e.id] == e {
			c.dropLocked(e.id, e)
		}
	})
}

// sanitize keeps a vault error code printable and short.
func sanitize(s string) string {
	b := make([]byte, 0, 64)
	for i := 0; i < len(s) && len(b) < 64; i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.' {
			b = append(b, ch)
		}
	}
	if len(b) == 0 {
		return "error"
	}
	return string(b)
}
