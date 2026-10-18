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
// Messages arrive in no guaranteed order (VAULT-MESSAGING §8.4; a failed
// deposit is sent again in a later flush, §8.3), so a grant set is
// trusted to widen what the connector holds only when it cannot be
// older than what the connector learned since (see Apply). Anything
// else may only narrow it.
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

	"github.com/vettid/vettid-vault/vms/envelope"
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
	// listGrace: at process start the background loop waits this long
	// before listing on its own, unless something asked for a list.
	listGrace = 30 * time.Second
	// minGap: Present uses a statement past its refresh time (but still
	// current) if it was successfully refreshed less than minGap ago: a
	// statement of the shortest lifetime (60 s) is always within a minute
	// of its end, so the quarter rule alone would refresh it on every
	// presentation.
	minGap = 15 * time.Second
	// bgMinGap: the background loop refreshes one grant's statement at
	// most once per bgMinGap after a successful refresh.
	bgMinGap = time.Minute
	// wantedFor: the background loop refreshes only the statements of
	// grants Present was asked for within this time; the others are
	// refreshed on demand.
	wantedFor = 15 * time.Minute
	// retryMax bounds the pause after failed requests.
	retryMax = 5 * time.Minute
	// idle is how long the background loop sleeps with nothing due.
	idle = time.Minute
	// listTries bounds the lists one List sends when answers keep being
	// overtaken by newer events.
	listTries = 3
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
	// ErrNoDevice: the connection has no device id, so no grant could be
	// checked as this agent's.
	ErrNoDevice = errors.New("the saved pairing has no device id: run `vettid-agent pair --restart`")
)

// Conn is what this package uses of vaultconn.Conn.
type Conn interface {
	RequestWithID(ctx context.Context, id, typ string, body json.RawMessage) (*vaultconn.Response, error)
	Access() pairing.Access
	DeviceID() string
	IdentityKey() ed25519.PublicKey
	LastContact() time.Time
}

// Options configure New.
type Options struct {
	// Saved is the record's `leash` member (nil: none), loaded by Bind.
	Saved json.RawMessage
	// VaultID and Name are shown by ConnectionInfo.
	VaultID, Name string
	// OnAnswer, if set, receives session_required and
	// owner_check_required answers to this package's requests, with the
	// access session as it was when the request was sent
	// (access.Manager.OnAnswer). It is called without locks held.
	OnAnswer func(code string, sentWith pairing.Access)
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

	mu       sync.Mutex
	conn     Conn
	deviceID string
	ik       ed25519.PublicKey
	// The grants as last applied, sorted by id; asOf: when.
	grants    []*Grant
	suspended bool
	asOf      time.Time
	saved     bool // grants, suspended and asOf hold something to save
	// gen counts what the connector learned that a list sent earlier may
	// not reflect: every applied leash.grant.updated, every narrowing,
	// not_found and forbidden. lists maps the id of each list this
	// process sent to gen at the time it was sent.
	gen   uint64
	lists map[string]uint64
	// lastSetMS: the vault time (the ULID of its message, in ms) of the
	// newest grant set applied in full; an update not newer only narrows.
	lastSetMS uint64
	// listed: a grant set was applied in full from a list sent in this
	// access session (in this process). Nothing is presented without it.
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
	// last asked for, last refreshed successfully, last wanted by
	// Present, consecutive failures, and grants the vault said are not in
	// force (not_found), until a list sent after that says otherwise.
	statements map[string]*statement
	fetched    map[string]time.Time
	refreshed  map[string]time.Time
	wanted     map[string]time.Time
	fails      map[string]int
	dead       map[string]bool
	started    time.Time
}

// New returns a Manager; Bind loads the saved grants (for display only
// until they are listed again).
func New(o Options) *Manager {
	if o.Now == nil {
		o.Now = time.Now
	}
	m := &Manager{o: o, now: o.Now, log: o.Log, wake: make(chan struct{}, 1), lists: map[string]uint64{},
		statements: map[string]*statement{}, fetched: map[string]time.Time{}, refreshed: map[string]time.Time{},
		wanted: map[string]time.Time{}, fails: map[string]int{}, dead: map[string]bool{}}
	if m.log == nil {
		m.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	m.started = m.now()
	return m
}

// Bind gives the Manager its connection, whose device id and identity
// key every grant must name, and loads the saved grants. It fails when
// the connection has no device id (nothing could be checked as this
// agent's). A saved member that does not parse is ignored (logged):
// nothing in it would be presented anyway.
func (m *Manager) Bind(conn Conn) error {
	id := conn.DeviceID()
	if id == "" {
		return ErrNoDevice
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conn, m.deviceID, m.ik = conn, id, conn.IdentityKey()
	if m.o.Saved != nil {
		s, err := decodeSaved(m.o.Saved, id)
		if err != nil {
			m.log.Warn("saved grants ignored", "err", err)
		} else {
			m.grants, m.suspended, m.asOf, m.saved = m.forMe(s.grants), s.suspended, s.asOf, true
		}
	}
	return nil
}

// forMe drops grants whose delegation names another agent key.
func (m *Manager) forMe(gs []*Grant) []*Grant {
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

// ulidMS returns a ULID's time in ms (ok false for anything else).
func ulidMS(id string) (uint64, bool) {
	if !envelope.ValidULID(id) {
		return 0, false
	}
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var ms uint64
	for i := 0; i < 10; i++ {
		ms = ms<<5 | uint64(strings.IndexByte(crockford, id[i]))
	}
	return ms, true
}

// How a grant set is applied.
type mode int

const (
	// modeList: the answer to a list this process sent, with nothing
	// learned since it was sent. It replaces the grants, ends a
	// suspension, revives grants answered not_found, and confirms them.
	modeList mode = iota
	// modeUpdate: a leash.grant.updated newer (by the vault's clock) than
	// any set applied in full. It replaces the grants, except that it
	// never revives a grant answered not_found, never lowers a grant's
	// version and never ends a suspension (a list sent after it does).
	modeUpdate
	// modeNarrow: anything else (an older update, an answer to a list
	// sent before something was learned, or to a list this process did
	// not send). It only removes: grants absent from it, or present in
	// another version, go; nothing is added; it can suspend but not
	// resume. A fresh list is asked for.
	modeNarrow
)

// Apply takes a batch of messages inside its save (vaultconn.Part):
// leash.grant.updated and answers to leash.grant.list (see mode);
// device.session.granted starts a session, whose grants are listed
// again before anything is presented; device.session.ended ends it.
// Applying the same batch again gives the same result or a narrower one.
func (m *Manager) Apply(batch []vaultconn.Message) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, msg := range batch {
		switch {
		case msg.Re == "" && msg.Type == "leash.grant.updated":
			md := modeNarrow
			if ms, ok := ulidMS(msg.ID); ok && ms > m.lastSetMS {
				md = modeUpdate
			}
			if m.applySet(msg.Body, md) && md == modeUpdate {
				m.lastSetMS, _ = ulidMS(msg.ID)
			}
			m.gen++
		case msg.Re != "" && msg.Type == "leash.grant.list" && msg.OK:
			md := modeNarrow
			g, mine := m.lists[msg.Re]
			delete(m.lists, msg.Re)
			if mine && g == m.gen {
				md = modeList
			}
			if m.applySet(msg.Body, md) && md == modeList {
				if ms, ok := ulidMS(msg.ID); ok && ms > m.lastSetMS {
					m.lastSetMS = ms
				}
			}
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

// applySet applies a grant set in a mode (m.mu held) and reports
// whether it parsed. A set that does not parse presents nothing until a
// list is applied; a grant that does not parse, is for another agent or
// appears twice is dropped.
func (m *Manager) applySet(body json.RawMessage, md mode) bool {
	now := m.now()
	var set grantSet
	if json.Unmarshal(body, &set) != nil || set.Grants == nil || set.Suspended == nil || len(*set.Grants) > MaxGrants {
		m.log.Warn("malformed grant set; nothing is presented until the grants are listed again")
		m.listed, m.needList = false, true
		m.signal()
		return false
	}
	var in []*Grant
	seen := map[string]int{}
	raw := map[string]*wireGrant{}
	for _, r := range *set.Grants {
		var w wireGrant
		if json.Unmarshal(r, &w) != nil {
			m.log.Warn("malformed grant dropped")
			continue
		}
		g, err := parseGrant(&w, m.deviceID)
		if err != nil {
			m.log.Warn("invalid grant dropped", "grant", logID(w.GrantID))
			continue
		}
		seen[g.ID]++
		raw[g.ID] = &w
		in = append(in, g)
	}
	in = slices.DeleteFunc(in, func(g *Grant) bool {
		if seen[g.ID] > 1 {
			m.log.Warn("grant listed twice dropped", "grant", g.ID)
			return true
		}
		return false
	})
	in = m.forMe(in)
	byID := map[string]*Grant{}
	for _, g := range in {
		byID[g.ID] = g
	}

	if md == modeNarrow {
		changed := false
		var kept []*Grant
		for _, g := range m.grants {
			if n := byID[g.ID]; n != nil && n.Version == g.Version {
				kept = append(kept, g)
				continue
			}
			delete(m.statements, g.ID)
			changed = true
		}
		if *set.Suspended && !m.suspended {
			m.suspended = true
			m.statements = map[string]*statement{}
			changed = true
		}
		if changed {
			m.grants, m.saved = kept, true
			m.gen++
		}
		m.needList = true
		m.signal()
		return true
	}

	// modeList and modeUpdate replace the grants.
	var gs []*Grant
	for _, g := range in {
		if md == modeUpdate && m.dead[g.ID] {
			continue // revived only by a list sent after the not_found
		}
		if old := m.find(g.ID); old != nil && g.Version < old.Version {
			m.log.Warn("grant in an older version dropped", "grant", g.ID)
			m.needList = true
			continue
		}
		gs = append(gs, g)
	}
	slices.SortFunc(gs, func(a, b *Grant) int { return strings.Compare(a.ID, b.ID) })
	suspended := *set.Suspended
	if md == modeUpdate && m.suspended && !suspended {
		suspended = true // a resume is confirmed by a list sent after it
		m.needList = true
	}
	// Each grant's statement is the one sent with it, if any (the vault
	// sends none for a grant not in force, while suspended or while held):
	// statements of grants no longer present, or sent without one, go.
	stmts := map[string]*statement{}
	if !suspended {
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
	}
	m.grants, m.suspended, m.asOf, m.saved = gs, suspended, now, true
	m.statements = stmts
	m.fails = map[string]int{}
	m.held = false
	if md == modeList {
		m.dead = map[string]bool{}
		m.listed = true
		if !m.needList {
			m.listFails, m.nextList = 0, time.Time{}
		}
	}
	m.signal()
	return true
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

func (m *Manager) answer(code string, sentWith pairing.Access) {
	if m.o.OnAnswer != nil {
		m.o.OnAnswer(code, sentWith)
	}
}

// List asks the vault for the grants (leash.grant.list) unless a list is
// in flight, in which case it waits for that one. The answer itself is
// applied by Apply, inside the save of its batch; it confirms the grants
// only if nothing was learned while it was on its way, otherwise List
// sends another (at most listTries in all).
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
		if !m.listed || m.needList {
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
	for try := 0; try < listTries; try++ {
		done, err := m.listOnce(ctx, conn)
		if done || err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.listFailed()
	m.mu.Unlock()
	return ErrUnconfirmed
}

// listOnce sends one list; done is false when its answer was overtaken
// (applied only as a narrowing).
func (m *Manager) listOnce(ctx context.Context, conn Conn) (done bool, err error) {
	now := m.now()
	id, err := envelope.NewULID(now)
	if err != nil {
		return false, ErrUnconfirmed
	}
	sentWith := conn.Access()
	m.mu.Lock()
	m.lists[id] = m.gen
	m.needList = false
	m.mu.Unlock()
	rctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	r, err := conn.RequestWithID(rctx, id, "leash.grant.list", json.RawMessage(`{}`))
	m.mu.Lock()
	if err != nil || !r.OK {
		delete(m.lists, id)
		m.needList = true
	}
	if err != nil {
		m.listFailed()
		m.mu.Unlock()
		if errors.Is(err, vaultconn.ErrRefused) {
			return true, err
		}
		return true, ErrUnconfirmed
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
		m.answer(code, sentWith)
		return true, out
	}
	defer m.mu.Unlock()
	if _, pending := m.lists[id]; pending {
		// Answered but never applied (no Apply saw it).
		delete(m.lists, id)
		m.needList = true
		m.listFailed()
		return true, ErrUnconfirmed
	}
	if m.needList {
		// Overtaken by something learned meanwhile (applied only as a
		// narrowing), or the set did not parse: list again.
		return false, nil
	}
	if !m.listed {
		m.listFailed()
		return true, ErrUnconfirmed
	}
	return true, nil
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
	sentWith := conn.Access()
	body, _ := json.Marshal(map[string]string{"grant_id": id})
	rctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	r, err := conn.RequestWithID(rctx, "", "leash.status.get", body)
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
			// expired): never presented again until a list sent after
			// this says otherwise.
			delete(m.statements, id)
			m.dead[id] = true
			m.gen++
			m.needList = true
			out = ErrNotGranted
		case "forbidden":
			// Suspended (§10.11): nothing is presented until a list sent
			// after this says otherwise.
			m.suspended, m.saved = true, true
			m.statements = map[string]*statement{}
			m.gen++
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
		m.answer(code, sentWith)
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
	if g == nil || m.dead[id] {
		// Revoked while the answer was on its way.
		return ErrNotGranted
	}
	if m.suspended {
		return ErrSuspended
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
	m.refreshed[id] = m.now()
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
// current, and before its refresh time or successfully refreshed less
// than minGap ago.
func (m *Manager) usable(id string, st *statement, now time.Time) bool {
	if st == nil || now.Before(st.issuedAt.Add(-leashwire.StatusSkew)) || !now.Before(st.notAfter) {
		return false
	}
	if now.Before(st.refreshAt()) {
		return true
	}
	r, ok := m.refreshed[id]
	return ok && now.Before(r.Add(minGap))
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
	m.wanted[id] = m.now()
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

// Run keeps the grants and statements current until ctx ends (AGENT-PLAN
// §3.3), while the connector has an access session and the vault is not
// held: it lists the grants when a list is wanted (a session started, a
// set could only narrow, not_found, forbidden, a resume to confirm; also
// while suspended), or if none was listed within listGrace of start; and
// it refreshes a statement that is due only for a grant Present was
// asked for within wantedFor, at most once per bgMinGap after a
// successful refresh. Other statements are refreshed by Present when it
// needs them. Bind must be called first.
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
	if m.needList || !m.listed {
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
		if !m.listed || m.needList {
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
		w, ok := m.wanted[g.ID]
		if g.del == nil || g.expired(now) || m.dead[g.ID] || !ok || !now.Before(w.Add(wantedFor)) {
			continue
		}
		at := now // no statement: as soon as allowed
		if st := m.statements[g.ID]; st != nil {
			at = st.refreshAt()
		}
		if r, ok := m.refreshed[g.ID]; ok {
			at = latest(at, r.Add(bgMinGap))
		}
		if f, ok := m.fetched[g.ID]; ok && m.fails[g.ID] > 0 {
			at = latest(at, f.Add(backoff(minGap, retryMax, m.fails[g.ID])))
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
