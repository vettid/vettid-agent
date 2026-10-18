// Package access is the connector's side of access sessions
// (AGENT-PLAN §2 AG8, §4.4, §6 A2.3; VAULT-MESSAGING §6.8): it knows
// whether the connector has an access session, asks for one when a
// tool call needs it, within AG8's bounds and the vault's own
// (`too_soon`), and turns the vault's session_required and
// owner_check_required answers into the connector's state.
//
// The session itself is kept by internal/vaultconn, which saves
// device.session.granted and .ended with the batch that carried them;
// this package reads it there (Conn.Access) and writes what it learns
// from probes and answers back (Conn.CompareAndSetAccess, against the
// session as it was when the request was sent).
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// AG8's bounds, and the request's default length.
const (
	// QuietAfterRefusal: no automatic request for 10 minutes after a
	// denial or a request that expired unanswered.
	QuietAfterRefusal = 10 * time.Minute
	// MaxPerHour automatic requests in any hour.
	MaxPerHour = 6
	// DefaultSeconds is the access asked for when the operator set none
	// (1 hour; the vault allows 60 s to 24 h).
	DefaultSeconds = 3600
	// RequestTimeout bounds one request to the vault: a request can wait
	// for Run's goroutine up to a save-failure pause (30 s) plus the
	// vault's answer (§8.1: 30 s).
	RequestTimeout = 90 * time.Second
)

// Operator texts (AGENT-PLAN §11), with the stable codes of AGENT-PLAN
// §4.1.
var (
	ErrAccessRequested = &Error{Code: "access_requested", Text: "This agent needs access to your vault. Allow it on your phone, then try again."}
	ErrAccessDenied    = &Error{Code: "access_denied", Text: "Access was declined on your phone."}
	ErrOwnerCheck      = &Error{Code: "owner_check_required", Text: "Your vault is waiting for your daily check. Open VettID on your phone."}
	ErrUnreachable     = &Error{Code: "vault_unreachable", Text: "Your vault did not answer. It may be locked; unlock it on your phone."}
)

// Error is an access outcome with a stable code (AGENT-PLAN §4.1).
type Error struct {
	Code string
	Text string
	// Until, if set, is when a new automatic request may be sent.
	Until time.Time
}

func (e *Error) Error() string { return e.Text }

// Is matches by code, so that an Error with Until matches its sentinel.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// quiet returns an Error for a request that may not be sent before
// until (chosen texts; AGENT-PLAN §11 drafts none for these).
func quiet(base *Error, until time.Time, why string) *Error {
	return &Error{Code: base.Code, Until: until,
		Text: fmt.Sprintf("%s No new request is sent before %s (%s).", base.Text, until.Local().Format("15:04"), why)}
}

// Conn is what this package uses of vaultconn.Conn.
type Conn interface {
	Request(ctx context.Context, typ string, body json.RawMessage) (*vaultconn.Response, error)
	Access() pairing.Access
	CompareAndSetAccess(old, a pairing.Access) bool
}

// Manager applies AG8 for one connector. It is safe for concurrent use.
type Manager struct {
	conn    Conn
	now     func() time.Time
	seconds int

	mu sync.Mutex
	// outstanding: a device.session.request the vault accepted, waiting
	// for a decision until outExp; sending: one is being sent.
	outstanding bool
	outID       string
	outExp      time.Time
	sending     bool
	// quietUntil: after a denial or an unanswered request; denied says
	// which.
	quietUntil time.Time
	denied     bool
	// allowedAfter: the vault's too_soon.
	allowedAfter time.Time
	// sent: times of automatic requests in the last hour.
	sent []time.Time
	// held: the vault answered owner_check_required, or vault.status
	// says held.
	held bool
	// probing is set while an unknown session is being checked.
	probing *flight
	// statusAt: when CheckHold last sent vault.status; checking: one is
	// in flight; statusHook also receives its answer.
	statusAt   time.Time
	checking   bool
	statusHook func(ownerCheck string)
}

// flight is a request to the vault that runs in a goroutine of its own,
// so that a caller can stop waiting for it (its context ended) without
// cancelling it: done is closed when it ends, and err is then its
// outcome.
type flight struct {
	done chan struct{}
	err  error
}

func newFlight() *flight { return &flight{done: make(chan struct{})} }

// wait returns f's outcome, or ErrUnreachable if ctx ends first (the
// request goes on; what it learns is recorded when it ends).
func (f *flight) wait(ctx context.Context) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ErrUnreachable
	}
}

// New returns a Manager. seconds is the operator's default access
// length (0: DefaultSeconds); now may be nil.
func New(conn Conn, seconds int, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	if seconds == 0 {
		seconds = DefaultSeconds
	}
	return &Manager{conn: conn, now: now, seconds: seconds}
}

// active reports whether a is a session usable at now.
func active(a pairing.Access, now time.Time) bool {
	return a.State == pairing.AccessActive && (a.ExpiresAt.IsZero() || now.Before(a.ExpiresAt))
}

// Start checks a saved session at start (AGENT-PLAN §4.4; A2.3): the
// vault offers no message that tells an agent its current session, so a
// saved session that has not expired is checked with one
// leash.grant.list, which needs a session (session_required means it
// was ended while the connector was not running). The owner check comes
// from vaultconn's vault.status at start (OnStatus). An unknown session
// (after pairing) is checked on the first Ensure instead.
func (m *Manager) Start(ctx context.Context) error {
	if !active(m.conn.Access(), m.now()) {
		return nil
	}
	return m.probe(ctx)
}

// probe sends leash.grant.list and records what its answer says about
// the session. leash.grant.list is the request AGENT-PLAN §4.5 sends at
// every session start; it sends nothing to the member's phone.
func (m *Manager) probe(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	before := m.conn.Access()
	r, err := m.conn.Request(ctx, "leash.grant.list", json.RawMessage(`{}`))
	if err != nil {
		if errors.Is(err, vaultconn.ErrRefused) {
			return err
		}
		return ErrUnreachable
	}
	switch {
	case r.OK:
		if before.State != pairing.AccessActive {
			// A session exists, its expiry unknown (it was granted at
			// pairing or while the connector did not run): usable until
			// the vault answers session_required.
			m.setIfUnchanged(before, pairing.Access{State: pairing.AccessActive})
		}
		return nil
	case r.ErrorCode == "session_required":
		m.setIfUnchanged(before, pairing.Access{State: pairing.AccessNone})
		return nil
	case r.ErrorCode == "owner_check_required":
		m.mu.Lock()
		m.held = true
		m.mu.Unlock()
		return ErrOwnerCheck
	default:
		return fmt.Errorf("the vault answered %s", r.ErrorCode)
	}
}

// setIfUnchanged sets a unless a device.session event changed the
// session while the probe was in flight (one atomic compare-and-set on
// Conn).
func (m *Manager) setIfUnchanged(before, a pairing.Access) {
	m.conn.CompareAndSetAccess(before, a)
}

// Ensure is called by a tool call that needs an access session. It
// returns nil when there is one; otherwise an *Error: the request it
// sent or that is outstanding (ErrAccessRequested), a quiet period
// (ErrAccessRequested or ErrAccessDenied with Until), the vault held
// (ErrOwnerCheck), or the vault not answering (ErrUnreachable).
//
// AG8: at most one request outstanding; no automatic request for
// QuietAfterRefusal after a denial or a request that expired
// unanswered; at most MaxPerHour an hour; never before the vault's
// too_soon allowed_after.
//
// Ensure returns when ctx ends even if a request to the vault is still
// on its way (a tool call's budget, AGENT-PLAN §2 AG9): it then answers
// ErrUnreachable, and the request goes on in the background, bounded by
// RequestTimeout, with what it learns recorded when it ends (while a
// device.session.request is on its way, Ensure answers
// ErrAccessRequested and sends no other). A ctx that has already ended
// sends nothing.
func (m *Manager) Ensure(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrUnreachable
	}
	now := m.now()
	m.mu.Lock()
	if m.held {
		m.mu.Unlock()
		return ErrOwnerCheck
	}
	a := m.conn.Access()
	if active(a, now) {
		m.mu.Unlock()
		return nil
	}
	if a.State == pairing.AccessUnknown {
		// Check the session first (one probe at a time; callers that
		// arrive meanwhile wait for it and take its outcome: nothing was
		// sent to the phone for them).
		f := m.probing
		if f == nil {
			f = newFlight()
			m.probing = f
			go func() {
				err := m.probe(context.WithoutCancel(ctx))
				m.mu.Lock()
				f.err, m.probing = err, nil
				m.mu.Unlock()
				close(f.done)
			}()
		}
		m.mu.Unlock()
		if err := f.wait(ctx); err != nil {
			return err
		}
		return m.Ensure(ctx)
	}
	if m.outstanding && !now.Before(m.outExp) {
		// Expired unanswered (VAULT-MESSAGING §6.8: dropped after 10
		// minutes).
		m.outstanding = false
		m.quietUntil, m.denied = m.outExp.Add(QuietAfterRefusal), false
	}
	switch {
	case m.outstanding || m.sending:
		m.mu.Unlock()
		return ErrAccessRequested
	case now.Before(m.quietUntil) && m.denied:
		e := quiet(ErrAccessDenied, m.quietUntil, "the last request was declined")
		m.mu.Unlock()
		return e
	case now.Before(m.quietUntil):
		e := quiet(ErrAccessRequested, m.quietUntil, "the last request was not answered")
		m.mu.Unlock()
		return e
	case now.Before(m.allowedAfter):
		e := quiet(ErrAccessRequested, m.allowedAfter, "your vault allows one request every 10 minutes")
		m.mu.Unlock()
		return e
	}
	m.pruneSent(now)
	if len(m.sent) >= MaxPerHour {
		e := quiet(ErrAccessRequested, m.sent[0].Add(time.Hour), "at most 6 requests an hour")
		m.mu.Unlock()
		return e
	}
	m.sending = true
	m.sent = append(m.sent, now)
	m.mu.Unlock()
	f := newFlight()
	go func() {
		f.err = m.request(context.WithoutCancel(ctx))
		close(f.done)
	}()
	return f.wait(ctx)
}

func (m *Manager) pruneSent(now time.Time) {
	i := 0
	for i < len(m.sent) && !now.Before(m.sent[i].Add(time.Hour)) {
		i++
	}
	m.sent = m.sent[i:]
}

// request sends device.session.request (Ensure set m.sending).
func (m *Manager) request(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]int{"seconds": m.seconds})
	r, err := m.conn.Request(ctx, "device.session.request", body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sending = false
	if err != nil {
		if errors.Is(err, vaultconn.ErrRefused) {
			return err
		}
		return ErrUnreachable
	}
	now := m.now()
	switch {
	case r.OK:
		var b struct {
			RequestID string `json:"request_id"`
			Exp       string `json:"exp"`
		}
		exp := now.Add(QuietAfterRefusal) // the vault drops it after 10 minutes
		if json.Unmarshal(r.Body, &b) == nil {
			if t, err := time.Parse(time.RFC3339, b.Exp); err == nil && t.After(now) {
				exp = t
			}
		}
		m.outstanding, m.outID, m.outExp = true, b.RequestID, exp
		return ErrAccessRequested
	case r.ErrorCode == "too_soon":
		// The vault's bound (VAULT-MESSAGING 0.40.0 §6.8): wait until
		// allowed_after, never retry sooner. Without a readable time,
		// wait the whole 10 minutes.
		after := now.Add(QuietAfterRefusal)
		var b struct {
			AllowedAfter string `json:"allowed_after"`
		}
		if json.Unmarshal(r.Body, &b) == nil {
			if t, err := time.Parse(time.RFC3339, b.AllowedAfter); err == nil {
				after = t
			}
		}
		if after.After(m.allowedAfter) {
			m.allowedAfter = after
		}
		return quiet(ErrAccessRequested, m.allowedAfter, "your vault allows one request every 10 minutes")
	case r.ErrorCode == "owner_check_required":
		m.held = true
		return ErrOwnerCheck
	default:
		return fmt.Errorf("the vault refused the access request: %s", r.ErrorCode)
	}
}

// OnEvent takes the vault's events (vaultconn.Options.OnEvent). The
// session itself was already applied by vaultconn in the batch's save;
// this updates the request policy. Idempotent: an event delivered again
// changes nothing more.
func (m *Manager) OnEvent(ev vaultconn.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch ev.Type {
	case "device.session.granted":
		m.outstanding = false
		m.held = false
	case "device.session.ended":
		var b struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(ev.Body, &b)
		if b.Reason == "denied" {
			// Also after a restart that forgot the request. Delivered
			// again after a crash, it restarts the quiet period: the
			// cautious direction.
			m.outstanding = false
			m.quietUntil, m.denied = m.now().Add(QuietAfterRefusal), true
		}
	case "leash.grant.updated":
		// AGENT-PLAN §4.4: a grant update shows the hold has ended.
		m.held = false
	}
}

// OnStatus takes the owner check state of each vault.status
// (vaultconn.Options.OnStatus).
func (m *Manager) OnStatus(ownerCheck string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.held = ownerCheck == "held"
}

// HoldRecheck is how often, at most, CheckHold asks the vault whether
// it is still held (chosen; not in the spec).
const HoldRecheck = time.Minute

// Held reports whether the vault was last seen held (AGENT-PLAN §4.4).
func (m *Manager) Held() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.held
}

// SetStatusHook makes f receive the owner check state of each
// vault.status that CheckHold sends, after OnStatus (for internal/leash,
// which keeps its own hold). Call it before CheckHold is first used.
func (m *Manager) SetStatusHook(f func(ownerCheck string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusHook = f
}

// CheckHold sends vault.status in the background, at most once per
// HoldRecheck and one at a time, so that a hold ends promptly once the
// member has done the daily check (AGENT-PLAN §4.4: vault.status passes
// while the vault is held, and a successful one shows the hold ended).
// A tool call calls it while the vault is held; the vault's own
// vault.status at start and every 6 hours (internal/vaultconn) is not
// enough for that. The answer goes to OnStatus and the status hook.
func (m *Manager) CheckHold() {
	now := m.now()
	m.mu.Lock()
	if m.checking || (!m.statusAt.IsZero() && now.Before(m.statusAt.Add(HoldRecheck))) {
		m.mu.Unlock()
		return
	}
	m.checking, m.statusAt = true, now
	hook := m.statusHook
	m.mu.Unlock()
	go func() {
		defer func() {
			m.mu.Lock()
			m.checking = false
			m.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
		defer cancel()
		r, err := m.conn.Request(ctx, "vault.status", json.RawMessage(`{}`))
		if err != nil || !r.OK {
			return
		}
		var s struct {
			OwnerCheck struct {
				State string `json:"state"`
			} `json:"owner_check"`
		}
		if json.Unmarshal(r.Body, &s) != nil || s.OwnerCheck.State == "" {
			return
		}
		m.OnStatus(s.OwnerCheck.State)
		if hook != nil {
			hook(s.OwnerCheck.State)
		}
	}()
}

// Snapshot returns the access session; a caller takes it before
// sending a request and gives it to OnAnswer with the answer.
func (m *Manager) Snapshot() pairing.Access { return m.conn.Access() }

// OnAnswer takes the error code of any other request's answer, with the
// session as it was when that request was sent (Snapshot):
// session_required means that session has ended (expired or ended while
// the connector did not see it) and sets none, unless a grant or an end
// changed the session since; owner_check_required means the vault is
// held.
func (m *Manager) OnAnswer(code string, sentWith pairing.Access) {
	switch code {
	case "session_required":
		m.conn.CompareAndSetAccess(sentWith, pairing.Access{State: pairing.AccessNone})
	case "owner_check_required":
		m.mu.Lock()
		m.held = true
		m.mu.Unlock()
	}
}

// Describe says in plain words what a saved access session is at now
// (for `vettid-agent status`).
func Describe(a pairing.Access, now time.Time) string {
	switch {
	case a.State == pairing.AccessNone:
		return "none"
	case a.State == pairing.AccessActive && a.ExpiresAt.IsZero():
		return "active (its end is not known)"
	case a.State == pairing.AccessActive && now.Before(a.ExpiresAt):
		return "active until " + a.ExpiresAt.Local().Format("2006-01-02 15:04")
	case a.State == pairing.AccessActive:
		return "ended at " + a.ExpiresAt.Local().Format("2006-01-02 15:04")
	default:
		return "not known yet (checked with your vault on first use)"
	}
}
