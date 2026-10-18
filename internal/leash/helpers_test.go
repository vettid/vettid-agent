package leash

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/leashwire"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// Fixed public test keys (the seeds of the leash.json vectors).
var (
	credKey  = ed25519.NewKeyFromSeed(fill(0x30))
	agentKey = ed25519.NewKeyFromSeed(fill(0x31))
	vaultKey = ed25519.NewKeyFromSeed(fill(0x04))
	otherKey = ed25519.NewKeyFromSeed(fill(0x55))
)

func fill(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

const testAgent = "agent-device-1"

// gid returns a valid grant id ending in n (0-9).
func gid(n int) string { return fmt.Sprintf("01JB2Z6V9K3M4N5P6Q7R8S9T%02d", n) }

// spec describes a test grant.
type spec struct {
	id       string
	scope    string
	approval string
	ttl      time.Duration
	exp      time.Time
	conns    []string
	sub      ed25519.PublicKey // default agentKey's
	noStatus bool
	statusAt time.Time // default: the clock's now
	version  uint64
	tamper   func(w map[string]any)
	agentID  string
}

// grant builds a grant's wire form as the vault sends it to the agent:
// members, a delegation signed by credKey and, unless noStatus, a status
// statement signed by vaultKey issued at statusAt.
func grant(t *testing.T, now time.Time, s spec) json.RawMessage {
	t.Helper()
	if s.scope == "" {
		s.scope = "items.read"
	}
	if s.approval == "" {
		s.approval = "auto"
	}
	if s.ttl == 0 {
		s.ttl = 900 * time.Second
	}
	if s.sub == nil {
		s.sub = pub(agentKey)
	}
	if s.version == 0 {
		s.version = 1
	}
	if s.agentID == "" {
		s.agentID = testAgent
	}
	iat := now.Add(-time.Hour).Truncate(time.Second)
	d := &leashwire.Delegation{Iss: pub(credKey), Sub: s.sub, GrantID: s.id, Version: s.version,
		Scope: leashwire.Scope{Op: s.scope, Connections: s.conns}, Approval: s.approval,
		StatusIssuer: pub(vaultKey), StatusTTL: s.ttl, Nonce: fill(0x32)[:16], IssuedAt: iat, Expires: s.exp}
	w := map[string]any{"grant_id": s.id, "agent_id": s.agentID, "version": s.version, "scope": s.scope,
		"approval": s.approval, "status_ttl": int(s.ttl / time.Second), "issued_at": iat.Format(time.RFC3339)}
	if s.scope == leashwire.ScopeItems {
		d.Scope.Tags, d.Scope.Match, d.Scope.Access = []string{"work"}, "any", "read"
		w["tags"], w["match"], w["access"] = []string{"work"}, "any", "read"
	}
	if s.approval == "auto" || s.scope == leashwire.ScopeItems {
		d.Limits = &leashwire.Limits{PerHour: 60, PerDay: 1000}
		w["per_hour"], w["per_day"] = 60, 1000
	}
	if s.conns != nil {
		w["connections"] = s.conns
	}
	if !s.exp.IsZero() {
		w["expires_at"] = s.exp.UTC().Format(time.RFC3339)
	}
	db := d.Marshal()
	sig, err := leashwire.Sign(credKey, db)
	if err != nil {
		t.Fatal(err)
	}
	w["delegation"], w["sig"] = base64.StdEncoding.EncodeToString(db), base64.StdEncoding.EncodeToString(sig)
	if !s.noStatus {
		at := s.statusAt
		if at.IsZero() {
			at = now
		}
		st, ssig := status(t, db, at)
		w["status"], w["status_sig"] = base64.StdEncoding.EncodeToString(st), base64.StdEncoding.EncodeToString(ssig)
	}
	if s.tamper != nil {
		s.tamper(w)
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func status(t *testing.T, delegation []byte, at time.Time) (st, sig []byte) {
	t.Helper()
	s, err := leashwire.NewStatus(delegation, at)
	if err != nil {
		t.Fatal(err)
	}
	st = s.Marshal()
	sig, err = leashwire.SignStatus(vaultKey, st)
	if err != nil {
		t.Fatal(err)
	}
	return st, sig
}

// set builds a grant set body.
func set(t *testing.T, suspended bool, grants ...json.RawMessage) json.RawMessage {
	t.Helper()
	if grants == nil {
		grants = []json.RawMessage{}
	}
	b, err := json.Marshal(map[string]any{"grants": grants, "suspended": suspended})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeConn plays vaultconn.Conn: answers come from handlers; an OK
// leash.grant.list answer is applied to the Manager first, as vaultconn
// does inside the save of its batch.
type fakeConn struct {
	mu        sync.Mutex
	m         *Manager
	access    pairing.Access
	ik        ed25519.PublicKey
	sent      []string
	list      func() *vaultconn.Response
	statusGet func(id string) *vaultconn.Response
	err       error
}

func (f *fakeConn) Request(ctx context.Context, typ string, body json.RawMessage) (*vaultconn.Response, error) {
	f.mu.Lock()
	f.sent = append(f.sent, typ)
	list, sg, err := f.list, f.statusGet, f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var r *vaultconn.Response
	switch typ {
	case "leash.grant.list":
		if list == nil {
			return nil, fmt.Errorf("no list handler")
		}
		r = list()
		if r.OK {
			f.m.Apply([]vaultconn.Message{{ID: "r1", Type: typ, Re: "q1", OK: true, Body: r.Body}})
		}
	case "leash.status.get":
		var b struct {
			GrantID string `json:"grant_id"`
		}
		_ = json.Unmarshal(body, &b)
		if sg == nil {
			return nil, fmt.Errorf("no status handler")
		}
		r = sg(b.GrantID)
	default:
		return nil, fmt.Errorf("unexpected %s", typ)
	}
	return r, nil
}

func (f *fakeConn) Access() pairing.Access {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.access
}

func (f *fakeConn) setAccess(a pairing.Access) {
	f.mu.Lock()
	f.access = a
	f.mu.Unlock()
}

func (f *fakeConn) IdentityKey() ed25519.PublicKey { return f.ik }
func (f *fakeConn) LastContact() time.Time         { return time.Time{} }

func (f *fakeConn) count(typ string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.sent {
		if s == typ {
			n++
		}
	}
	return n
}

func ok(body json.RawMessage) *vaultconn.Response {
	return &vaultconn.Response{OK: true, Body: body}
}

func fail(code string) *vaultconn.Response {
	return &vaultconn.Response{ErrorCode: code}
}

// statusAnswer answers leash.status.get for g with a statement issued
// at the clock's now.
func statusAnswer(t *testing.T, c *clock, grants map[string]json.RawMessage) func(string) *vaultconn.Response {
	return func(id string) *vaultconn.Response {
		g, okk := grants[id]
		if !okk {
			return fail("not_found")
		}
		var w struct {
			Delegation []byte `json:"delegation"`
		}
		if err := json.Unmarshal(g, &w); err != nil {
			t.Error(err)
		}
		st, sig := status(t, w.Delegation, c.Now())
		b, _ := json.Marshal(map[string]any{"grant_id": id, "status": st, "status_sig": sig})
		return ok(b)
	}
}

// env is a Manager bound to a fakeConn with an active session.
type env struct {
	c *clock
	f *fakeConn
	m *Manager
}

func newEnv(t *testing.T) *env {
	t.Helper()
	c := &clock{t: time.Unix(1790856000, 0).UTC()}
	m := New(Options{DeviceID: testAgent, VaultID: "vault-1", Name: "test agent", Now: c.Now})
	f := &fakeConn{m: m, ik: pub(agentKey), access: pairing.Access{State: pairing.AccessActive}}
	m.Bind(f)
	return &env{c: c, f: f, m: m}
}

// listing makes the vault answer leash.grant.list with these grants.
func (e *env) listing(t *testing.T, suspended bool, grants ...json.RawMessage) {
	body := set(t, suspended, grants...)
	e.f.mu.Lock()
	e.f.list = func() *vaultconn.Response { return ok(body) }
	e.f.mu.Unlock()
}

func (e *env) update(t *testing.T, suspended bool, grants ...json.RawMessage) {
	e.m.Apply([]vaultconn.Message{{ID: "e1", Type: "leash.grant.updated", Body: set(t, suspended, grants...)}})
}
