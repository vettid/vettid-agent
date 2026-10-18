// Package leash keeps the connector's LEASH grants (AGENT-PLAN §4.5, §6
// A3.1; VAULT-MESSAGING §10.11): the grants and `suspended` from
// leash.grant.updated and leash.grant.list, the status statements that
// keep each delegation presentable, and what leash.connection_info
// returns.
//
// Rules (AGENT-PLAN §4.5):
//
//   - Grants are re-read with leash.grant.list at every access session
//     start: the vault sends leash.grant.updated only within a session,
//     so saved grants and events alone are never trusted for
//     presentation.
//   - A delegation is presented only if it is among the current grants,
//     unexpired, while the connector has an access session, after the
//     grants were listed in that session, and never while the vault says
//     the agent is suspended.
//   - A status statement is refreshed when less than a quarter of its
//     lifetime (at least a minute) remains.
//
// The grants are saved in the record's `leash` member with the batch
// that carried them (vaultconn.Part), before the batch is acknowledged;
// status statements are kept in memory only (the list at the next
// session start brings fresh ones).
//
// Logs carry grant ids, types and error codes, never delegations or
// statements.
package leash

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/leashwire"
	"github.com/vettid/vettid-vault/vms/suite"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// Timing (chosen; not in the spec).
const (
	// RequestTimeout bounds one request to the vault (as internal/access).
	RequestTimeout = access.RequestTimeout
	// listGrace: at process start internal/access checks a saved session
	// with a leash.grant.list, whose answer is applied here; the
	// background loop sends its own only if none was applied by then.
	listGrace = 30 * time.Second
	// minGap is the shortest time between two leash.status.get for one
	// grant: a statement of the shortest lifetime (60 s) is always within
	// a minute of its end, so the quarter rule alone would refresh it
	// continuously.
	minGap = 15 * time.Second
	// retryMax bounds the pause after failed requests.
	retryMax = 5 * time.Minute
	// idle is how long the background loop sleeps with nothing due.
	idle = time.Minute
)

// Error is an outcome with a stable code (AGENT-PLAN §4.1).
type Error struct {
	Code string
	Text string
}

func (e *Error) Error() string { return e.Text }

// Is matches by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

var (
	// ErrSuspended: the vault paused this agent (AGENT-PLAN §11).
	ErrSuspended = &Error{Code: "suspended", Text: "Your vault paused this agent after repeated refused requests. You can resume it on your phone."}
	// ErrNotGranted: no such current grant (chosen text).
	ErrNotGranted = &Error{Code: "not_granted", Text: "Your vault has given this agent no such grant. You can change its permissions on your phone."}
	// ErrNotPresentable: the grant carries no delegation the vault serves
	// (chosen text).
	ErrNotPresentable = &Error{Code: "not_presentable", Text: "This grant has no signed delegation. Issue it again on your phone."}
	// ErrNoSession: no access session, so the grants cannot be confirmed
	// (chosen text; the tool asks for one through internal/access).
	ErrNoSession = &Error{Code: "session_required", Text: "This agent has no access session with your vault, so its grants cannot be confirmed."}
	// ErrUnconfirmed: the grants have not been listed in this session
	// and could not be (chosen text).
	ErrUnconfirmed = &Error{Code: "vault_unreachable", Text: "This agent's grants could not be confirmed with your vault. Try again."}
)

// Conn is what this package uses of vaultconn.Conn.
type Conn interface {
	Request(ctx context.Context, typ string, body json.RawMessage) (*vaultconn.Response, error)
	Access() pairing.Access
	IdentityKey() ed25519.PublicKey
	LastContact() time.Time
}

// Options configure New.
type Options struct {
	// Saved is the record's `leash` member (nil: none).
	Saved json.RawMessage
	// DeviceID is this agent's device id (a grant for another agent is
	// dropped); VaultID and Name are shown by ConnectionInfo.
	DeviceID, VaultID, Name string
	// OnAnswer, if set, receives session_required and
	// owner_check_required answers to this package's requests
	// (access.Manager.OnAnswer). It is called without locks held.
	OnAnswer func(code string)
	Now      func() time.Time
	Log      *slog.Logger
}

// Manager keeps one connector's grants. It is safe for concurrent use;
// Apply and Snapshot are called by vaultconn in Run's goroutine.
type Manager struct {
	o    Options
	now  func() time.Time
	log  *slog.Logger
	wake chan struct{}

	mu   sync.Mutex
	conn Conn
	ik   ed25519.PublicKey
	// The grants as the vault last sent them, sorted by id; asOf: when.
	grants    []*Grant
	suspended bool
	asOf      time.Time
	saved     bool // grants, suspended and asOf hold something to save
	// listed: a leash.grant.list answer was applied since the access
	// session started (in this process). Nothing is presented without it.
	listed   bool
	needList bool
	listing  chan struct{} // closed when the list in flight ends
	// listFails and nextList pace the background loop's lists.
	listFails int
	nextList  time.Time
	// held: the vault answered owner_check_required; nothing is refreshed
	// until leash.grant.updated or vault.status shows the hold ended.
	held bool
	// Statements by grant id (memory only), and per grant: when one was
	// last asked for, consecutive failures, and grants the vault said are
	// not in force (not_found) until the next grant set.
	statements map[string]*statement
	fetched    map[string]time.Time
	fails      map[string]int
	dead       map[string]bool
	started    time.Time
}

// New returns a Manager with the saved grants (for display only until
// they are listed again). A saved member that does not parse is
// ignored (logged): nothing in it would be presented anyway.
func New(o Options) *Manager {
	if o.Now == nil {
		o.Now = time.Now
	}
	m := &Manager{o: o, now: o.Now, log: o.Log, wake: make(chan struct{}, 1),
		statements: map[string]*statement{}, fetched: map[string]time.Time{}, fails: map[string]int{}, dead: map[string]bool{}}
	if m.log == nil {
		m.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	m.started = m.now()
	if o.Saved != nil {
		s, err := decodeSaved(o.Saved, o.DeviceID)
		if err != nil {
			m.log.Warn("saved grants ignored", "err", err)
		} else {
			m.grants, m.suspended, m.asOf, m.saved = s.grants, s.suspended, s.asOf, true
		}
	}
	return m
}

// Bind gives the Manager its connection; Apply drops grants whose
// delegation is not for conn's identity key.
func (m *Manager) Bind(conn Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conn, m.ik = conn, conn.IdentityKey()
	m.grants = m.forMe(m.grants)
}

// forMe drops grants whose delegation names another agent key.
func (m *Manager) forMe(gs []*Grant) []*Grant {
	if m.ik == nil {
		return gs
	}
	return slices.DeleteFunc(slices.Clone(gs), func(g *Grant) bool {
		if g.del != nil && !suite.EqualPublic(g.del.Sub, m.ik) {
			m.log.Warn("grant dropped: its delegation names another agent", "grant", g.ID)
			return true
		}
		return false
	})
}

func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Apply takes a batch of messages inside its save (vaultconn.Part), in
// order: leash.grant.updated and answers to leash.grant.list replace the
// grants; device.session.granted starts a session, whose grants are
// listed again before anything is presented; device.session.ended ends
// it. Applying the same batch again gives the same result.
func (m *Manager) Apply(batch []vaultconn.Message) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, msg := range batch {
		switch {
		case msg.Re == "" && msg.Type == "leash.grant.updated":
			m.applySet(msg.Body, false)
		case msg.Re != "" && msg.Type == "leash.grant.list" && msg.OK:
			m.applySet(msg.Body, true)
		case msg.Re == "" && msg.Type == "device.session.granted":
			m.listed, m.needList = false, true
			m.listFails, m.nextList = 0, time.Time{}
			m.signal()
		case msg.Re == "" && msg.Type == "device.session.ended":
			m.listed = false
		}
	}
}

// grantSet is the body of leash.grant.updated and of an agent's
// leash.grant.list answer: all of its grants, and whether it is
// suspended.
type grantSet struct {
	Grants    *[]json.RawMessage `json:"grants"`
	Suspended *bool              `json:"suspended"`
}

// applySet replaces the grants with a grant set (m.mu held). A set that
// does not parse presents nothing until a list parses; a grant that does
// not parse, is for another agent or appears twice is dropped.
func (m *Manager) applySet(body json.RawMessage, fromList bool) {
	now := m.now()
	var set grantSet
	if json.Unmarshal(body, &set) != nil || set.Grants == nil || set.Suspended == nil || len(*set.Grants) > MaxGrants {
		m.log.Warn("malformed grant set; nothing is presented until the grants are listed again", "list", fromList)
		m.listed, m.needList = false, true
		m.signal()
		return
	}
	var gs []*Grant
	seen := map[string]int{}
	raw := map[string]*wireGrant{}
	for _, r := range *set.Grants {
		var w wireGrant
		if json.Unmarshal(r, &w) != nil {
			m.log.Warn("malformed grant dropped")
			continue
		}
		g, err := parseGrant(&w, m.o.DeviceID)
		if err != nil {
			m.log.Warn("invalid grant dropped", "grant", logID(w.GrantID))
			continue
		}
		seen[g.ID]++
		raw[g.ID] = &w
		gs = append(gs, g)
	}
	gs = slices.DeleteFunc(gs, func(g *Grant) bool {
		if seen[g.ID] > 1 {
			m.log.Warn("grant listed twice dropped", "grant", g.ID)
			return true
		}
		return false
	})
	gs = m.forMe(gs)
	slices.SortFunc(gs, func(a, b *Grant) int { return strings.Compare(a.ID, b.ID) })
	// Each grant's statement is the one sent with it, if any (the vault
	// sends none for a grant not in force, while suspended or while held):
	// statements of grants no longer present, or sent without one, go.
	stmts := map[string]*statement{}
	for _, g := range gs {
		w := raw[g.ID]
		if w.Status == nil && w.StatusSig == nil {
			continue
		}
		st, err := checkStatement(g, w.Status, w.StatusSig, w.Rotations, now)
		if err != nil {
			m.log.Warn("status statement refused", "grant", g.ID)
			continue
		}
		stmts[g.ID] = st
	}
	m.grants, m.suspended, m.asOf, m.saved = gs, *set.Suspended, now, true
	m.statements = stmts
	m.dead, m.fails = map[string]bool{}, map[string]int{}
	m.held = false
	if fromList {
		m.listed, m.needList = true, false
		m.listFails, m.nextList = 0, time.Time{}
	}
	m.signal()
}

// Snapshot returns the record's `leash` member (vaultconn.Part).
func (m *Manager) Snapshot() json.RawMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.saved {
		return m.o.Saved
	}
	b, err := encodeSaved(m.grants, m.suspended, m.asOf)
	if err != nil {
		return m.o.Saved
	}
	return b
}

// OnStatus takes the owner check state of each vault.status
// (vaultconn.Options.OnStatus): anything but "held" ends a hold.
func (m *Manager) OnStatus(ownerCheck string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ownerCheck != "held" && m.held {
		m.held = false
		m.signal()
	}
}

// activeAt reports whether a is a session usable at now.
func activeAt(a pairing.Access, now time.Time) bool {
	return a.State == pairing.AccessActive && (a.ExpiresAt.IsZero() || now.Before(a.ExpiresAt))
}

func (m *Manager) answer(code string) {
	if m.o.OnAnswer != nil {
		m.o.OnAnswer(code)
	}
}

// List asks the vault for the grants (leash.grant.list) unless a list is
// in flight, in which case it waits for that one. The answer itself is
// applied by Apply, inside the save of its batch.
func (m *Manager) List(ctx context.Context) error {
	m.mu.Lock()
	if m.conn == nil {
		m.mu.Unlock()
		return ErrUnconfirmed
	}
	if ch := m.listing; ch != nil {
		m.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.listed {
			return ErrUnconfirmed
		}
		return nil
	}
	ch := make(chan struct{})
	m.listing = ch
	conn := m.conn
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.listing = nil
		close(ch)
		m.mu.Unlock()
	}()

	rctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	r, err := conn.Request(rctx, "leash.grant.list", json.RawMessage(`{}`))
	m.mu.Lock()
	if err != nil {
		m.listFailed()
		m.mu.Unlock()
		if errors.Is(err, vaultconn.ErrRefused) {
			return err
		}
		return ErrUnconfirmed
	}
	if !r.OK {
		code := r.ErrorCode
		var out error
		switch code {
		case "session_required":
			m.listed = false
			out = ErrNoSession
		case "owner_check_required":
			m.held = true
			out = access.ErrOwnerCheck
		default:
			m.listFailed()
			out = fmt.Errorf("%w (the vault answered %s)", ErrUnconfirmed, logID(code))
		}
		m.mu.Unlock()
		m.answer(code)
		return out
	}
	ok := m.listed
	if !ok {
		// Answered, but the set did not parse (Apply logged it).
		m.listFailed()
	}
	m.mu.Unlock()
	if !ok {
		return ErrUnconfirmed
	}
	return nil
}

func (m *Manager) listFailed() {
	m.listFails++
	m.nextList = m.now().Add(backoff(minGap, retryMax, m.listFails))
}

// backoff returns base doubled n-1 times, at most max.
func backoff(base, limit time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

// refresh asks the vault for a fresh status statement of one grant
// (leash.status.get).
func (m *Manager) refresh(ctx context.Context, id string) error {
	m.mu.Lock()
	conn := m.conn
	m.fetched[id] = m.now()
	m.mu.Unlock()
	if conn == nil {
		return ErrUnconfirmed
	}
	body, _ := json.Marshal(map[string]string{"grant_id": id})
	rctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	r, err := conn.Request(rctx, "leash.status.get", body)
	m.mu.Lock()
	if err != nil {
		m.fails[id]++
		m.mu.Unlock()
		if errors.Is(err, vaultconn.ErrRefused) {
			return err
		}
		return access.ErrUnreachable
	}
	if !r.OK {
		code := r.ErrorCode
		var out error
		switch code {
		case "not_found":
			// Not this agent's grant or not in force (revoked or
			// expired): drop its statement and list the grants again.
			delete(m.statements, id)
			m.dead[id] = true
			m.needList = true
			out = ErrNotGranted
		case "forbidden":
			// Suspended (§10.11): nothing is presented until a grant set
			// says otherwise.
			m.suspended, m.saved = true, true
			m.statements = map[string]*statement{}
			m.needList = true
			out = ErrSuspended
		case "owner_check_required":
			m.held = true
			out = access.ErrOwnerCheck
		case "session_required":
			m.listed = false
			out = ErrNoSession
		default:
			m.fails[id]++
			out = fmt.Errorf("%w (the vault answered %s)", ErrUnconfirmed, logID(code))
		}
		m.mu.Unlock()
		m.answer(code)
		m.signal()
		return out
	}
	defer m.mu.Unlock()
	var b struct {
		GrantID   string            `json:"grant_id"`
		Status    []byte            `json:"status"`
		StatusSig []byte            `json:"status_sig"`
		Rotations []json.RawMessage `json:"rotations"`
	}
	g := m.find(id)
	if g == nil {
		// Revoked while the answer was on its way.
		return ErrNotGranted
	}
	if json.Unmarshal(r.Body, &b) != nil || b.GrantID != id {
		m.fails[id]++
		return ErrUnconfirmed
	}
	st, err := checkStatement(g, b.Status, b.StatusSig, b.Rotations, m.now())
	if err != nil {
		m.fails[id]++
		m.log.Warn("status statement refused", "grant", id)
		return ErrUnconfirmed
	}
	m.statements[id] = st
	m.fails[id] = 0
	return nil
}

// find returns the current grant id (m.mu held).
func (m *Manager) find(id string) *Grant {
	for _, g := range m.grants {
		if g.ID == id {
			return g
		}
	}
	return nil
}

// presentable returns the grant id if it may be presented at now
// (m.mu held): the grants were listed in this access session, the agent
// is not suspended, and the grant is current, unexpired, not refused by
// the vault, and carries a delegation for this agent.
func (m *Manager) presentable(id string, now time.Time) (*Grant, error) {
	if m.suspended {
		return nil, ErrSuspended
	}
	if m.conn == nil || !activeAt(m.conn.Access(), now) {
		return nil, ErrNoSession
	}
	if !m.listed {
		return nil, ErrUnconfirmed
	}
	g := m.find(id)
	if g == nil || g.expired(now) || m.dead[id] {
		return nil, ErrNotGranted
	}
	if g.del == nil || m.ik == nil || !suite.EqualPublic(g.del.Sub, m.ik) {
		return nil, ErrNotPresentable
	}
	return g, nil
}

// usable reports whether st may be presented at now without a refresh:
// before its refresh time, or (just refreshed) still current.
func (m *Manager) usable(id string, st *statement, now time.Time) bool {
	if st == nil || now.Before(st.issuedAt.Add(-leashwire.StatusSkew)) || !now.Before(st.notAfter) {
		return false
	}
	return now.Before(st.refreshAt()) || now.Before(m.fetched[id].Add(minGap))
}

// Present returns what this agent shows a relying party for one of its
// grants (VAULT-MESSAGING §10.11 "Status statements"): the delegation,
// the member's signature, a current status statement and the vault's
// rotation chain, the statement refreshed first if less than a quarter
// of its lifetime (at least a minute) remains. It lists the grants first
// if they were not listed in this access session. It never presents a
// grant that is not among the current grants, expired or refused by the
// vault, nor anything while the agent is suspended or has no access
// session.
func (m *Manager) Present(ctx context.Context, id string) (*leashwire.Presented, error) {
	m.mu.Lock()
	_, err := m.presentable(id, m.now())
	m.mu.Unlock()
	if errors.Is(err, ErrUnconfirmed) {
		if err := m.List(ctx); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	m.mu.Lock()
	now := m.now()
	g, err := m.presentable(id, now)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if st := m.statements[id]; m.usable(id, st, now) {
		defer m.mu.Unlock()
		return presented(g, st), nil
	}
	m.mu.Unlock()
	if err := m.refresh(ctx, id); err != nil {
		return nil, err
	}
	// Checked again: a grant set or a refusal may have arrived meanwhile.
	m.mu.Lock()
	defer m.mu.Unlock()
	now = m.now()
	g, err = m.presentable(id, now)
	if err != nil {
		return nil, err
	}
	st := m.statements[id]
	if !m.usable(id, st, now) {
		return nil, ErrUnconfirmed
	}
	return presented(g, st), nil
}

// Run keeps the statements fresh until ctx ends (AGENT-PLAN §3.3): while
// the connector has an access session and the vault is not held, it
// lists the grants when a session started (or if internal/access's
// check at start brought none within listGrace), and refreshes each
// presentable grant's statement at its refresh time. Bind must be
// called first.
func (m *Manager) Run(ctx context.Context) {
	for {
		next := m.step(ctx)
		d := max(next.Sub(m.now()), 50*time.Millisecond)
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-m.wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// step does what is due and returns when to look again.
func (m *Manager) step(ctx context.Context) time.Time {
	now := m.now()
	m.mu.Lock()
	if m.conn == nil || m.held || !activeAt(m.conn.Access(), now) {
		m.mu.Unlock()
		return now.Add(idle)
	}
	if !m.listed {
		at := m.nextList
		if !m.needList {
			at = latest(at, m.started.Add(listGrace))
		}
		m.mu.Unlock()
		if now.Before(at) {
			return earliest(at, now.Add(idle))
		}
		if err := m.List(ctx); err != nil && ctx.Err() == nil {
			m.log.Warn("grants not listed", "err", errText(err))
		}
		m.mu.Lock()
		if !m.listed {
			next := m.nextList
			m.mu.Unlock()
			return earliest(next, now.Add(idle))
		}
	}
	if m.suspended {
		m.mu.Unlock()
		return now.Add(idle)
	}
	var due []string
	next := now.Add(idle)
	for _, g := range m.grants {
		if g.del == nil || g.expired(now) || m.dead[g.ID] {
			continue
		}
		at := now // no statement: as soon as allowed
		if st := m.statements[g.ID]; st != nil {
			at = st.refreshAt()
		}
		if f, ok := m.fetched[g.ID]; ok {
			at = latest(at, f.Add(backoff(minGap, retryMax, m.fails[g.ID]+1)))
		}
		if !now.Before(at) {
			due = append(due, g.ID)
		} else {
			next = earliest(next, at)
		}
	}
	m.mu.Unlock()
	for _, id := range due {
		if ctx.Err() != nil {
			break
		}
		if err := m.refresh(ctx, id); err != nil {
			m.log.Warn("status statement not refreshed", "grant", id, "err", errText(err))
		}
	}
	if len(due) > 0 {
		return now // look again at once: refresh times moved
	}
	return next
}

func earliest(a, b time.Time) time.Time {
	if a.IsZero() || b.Before(a) {
		return b
	}
	return a
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// errText is an error for the log: a code, never a body.
func errText(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	var a *access.Error
	if errors.As(err, &a) {
		return a.Code
	}
	if errors.Is(err, vaultconn.ErrRefused) {
		return "refused"
	}
	return "error"
}

// logID keeps an id or code from the vault printable and short for logs
// and texts.
func logID(s string) string {
	b := make([]byte, 0, 64)
	for i := 0; i < len(s) && len(b) < 64; i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' || ch == '.' {
			b = append(b, ch)
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}
