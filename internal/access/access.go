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
// from probes and answers back (Conn.SetAccess).
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
	SetAccess(pairing.Access)
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
	// probing: an unknown session is being checked.
	probing bool
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
// session while the probe was in flight.
func (m *Manager) setIfUnchanged(before, a pairing.Access) {
	if m.conn.Access() == before {
		m.conn.SetAccess(a)
	}
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
func (m *Manager) Ensure(ctx context.Context) error {
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
		if m.probing {
			m.mu.Unlock()
			return ErrAccessRequested
		}
		m.probing = true
		m.mu.Unlock()
		err := m.probe(ctx)
		m.mu.Lock()
		m.probing = false
		m.mu.Unlock()
		if err != nil {
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
	return m.request(ctx)
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

// OnAnswer takes the error code of any other request's answer:
// session_required means the session has ended (expired or ended while
// the connector did not see it); owner_check_required means the vault
// is held.
func (m *Manager) OnAnswer(code string) {
	switch code {
	case "session_required":
		if m.conn.Access().State != pairing.AccessNone {
			m.conn.SetAccess(pairing.Access{State: pairing.AccessNone})
		}
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
