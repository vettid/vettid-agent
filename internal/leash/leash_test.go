package leash

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/leashwire"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

var ctx = context.Background()

func mustPresent(t *testing.T, e *env, id string) *leashwire.Presented {
	t.Helper()
	p, err := e.m.Present(ctx, id)
	if err != nil {
		t.Fatalf("present %s: %v", id, err)
	}
	if _, err := leashwire.VerifyPresented(pub(credKey), p, e.c.Now()); err != nil {
		t.Fatalf("presented %s does not verify: %v", id, err)
	}
	return p
}

func refused(t *testing.T, e *env, id string, want error) {
	t.Helper()
	p, err := e.m.Present(ctx, id)
	if p != nil || err == nil {
		t.Fatalf("present %s: presented", id)
	}
	if want != nil && !errors.Is(err, want) {
		t.Fatalf("present %s: %v, want %v", id, err, want)
	}
}

// TestRevokedNeverPresented: a grant that leaves the grant set (revoked,
// leash.grant.updated) is never presented again, even with a statement
// still current; the others stay presentable.
func TestRevokedNeverPresented(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2), scope: "message.send", approval: "ask"})
	e.listing(t, false, g1, g2)
	mustPresent(t, e, gid(1))
	mustPresent(t, e, gid(2))
	e.update(t, false, g2) // gid(1) revoked
	refused(t, e, gid(1), ErrNotGranted)
	mustPresent(t, e, gid(2))
	for _, gi := range e.m.ConnectionInfo().Grants {
		if gi.GrantID == gid(1) {
			t.Error("connection info shows the revoked grant")
		}
	}
	// The revoked grant comes back in no later step either (the list the
	// update asked for no longer has it).
	e.listing(t, false, g2)
	e.c.Add(10 * time.Minute)
	e.f.mu.Lock()
	e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1, gid(2): g2})
	e.f.mu.Unlock()
	e.m.step(ctx)
	refused(t, e, gid(1), ErrNotGranted)
}

// TestRevokedDuringRefresh: a revocation that arrives while a statement
// is being refreshed wins: the refreshed statement is not presented.
func TestRevokedDuringRefresh(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1), noStatus: true})
	e.listing(t, false, g1)
	ans := statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1})
	e.f.statusGet = func(id string) *vaultconn.Response {
		e.update(t, false) // revoked while the answer is on its way
		return ans(id)
	}
	refused(t, e, gid(1), ErrNotGranted)
}

// TestNotFoundStopsPresenting: a vault that answers leash.status.get
// not_found (revoked without an update reaching the connector) stops
// the grant at once, and the grants are listed again.
func TestNotFoundStopsPresenting(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.c.Add(700 * time.Second) // past the refresh time of a 900 s statement
	e.f.statusGet = func(string) *vaultconn.Response { return fail("not_found") }
	refused(t, e, gid(1), ErrNotGranted)
	// Still current by time, but never presented.
	refused(t, e, gid(1), ErrNotGranted)
	e.m.mu.Lock()
	need := e.m.needList
	e.m.mu.Unlock()
	if !need {
		t.Error("no new list wanted")
	}
}

// TestExpiredNeverPresented: a grant past its expires_at is not
// presented or shown, whatever its statement says.
func TestExpiredNeverPresented(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	exp := now.Add(10 * time.Minute)
	g1 := grant(t, now, spec{id: gid(1), exp: exp})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.c.Add(10 * time.Minute)
	refused(t, e, gid(1), ErrNotGranted)
	if n := len(e.m.ConnectionInfo().Grants); n != 0 {
		t.Errorf("connection info shows %d grants", n)
	}
}

// TestNothingWhileSuspended: while the vault says the agent is
// suspended nothing is presented (even with statements attached), no
// statement is refreshed, and connection info says so; a grant set that
// ends it restores presentation.
func TestNothingWhileSuspended(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2), noStatus: true})
	e.listing(t, true, g1, g2)
	e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1, gid(2): g2})
	refused(t, e, gid(1), ErrSuspended)
	refused(t, e, gid(2), ErrSuspended)
	e.m.step(ctx)
	e.c.Add(time.Hour)
	e.m.step(ctx)
	if n := e.f.count("leash.status.get"); n != 0 {
		t.Errorf("%d statements asked for while suspended", n)
	}
	in := e.m.ConnectionInfo()
	if !in.Suspended || len(in.Grants) != 2 {
		t.Errorf("info: %+v", in)
	}
	for _, gi := range in.Grants {
		if gi.StatusUntil != nil {
			t.Error("a statement shown while suspended")
		}
	}
	// Resumed (leash.agent.resume sends leash.grant.updated): the update
	// alone does not end the suspension; the list the background loop
	// sends then (while suspended) does.
	now = e.c.Now()
	g1 = grant(t, now, spec{id: gid(1)})
	e.update(t, false, g1)
	refused(t, e, gid(1), ErrSuspended)
	e.listing(t, false, g1)
	e.m.step(ctx)
	mustPresent(t, e, gid(1))
}

// TestForbiddenSuspends: leash.status.get answered forbidden (the vault
// suspended the agent) stops every presentation at once, and the
// suspension is saved.
func TestForbiddenSuspends(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.listing(t, false, g1, g2)
	mustPresent(t, e, gid(2))
	e.c.Add(700 * time.Second)
	e.f.statusGet = func(string) *vaultconn.Response { return fail("forbidden") }
	refused(t, e, gid(1), ErrSuspended)
	e.c.Add(-650 * time.Second) // gid(2)'s statement would be fresh again
	refused(t, e, gid(2), ErrSuspended)
	s, err := ReadSaved(e.m.Snapshot(), testAgent, e.c.Now())
	if err != nil || !s.Suspended {
		t.Errorf("saved: %+v %v", s, err)
	}
}

// TestRefreshAtQuarter: a statement is refreshed once less than a
// quarter of its lifetime remains, and not before; for a short lifetime
// the margin is at least a minute.
func TestRefreshAtQuarter(t *testing.T) {
	for _, tc := range []struct {
		ttl, at time.Duration // at: the refresh time after issued_at
	}{
		{900 * time.Second, 675 * time.Second}, // 900 - 900/4
		{3600 * time.Second, 2700 * time.Second},
		{120 * time.Second, 60 * time.Second}, // a quarter is 30 s: at least a minute
	} {
		t.Run(tc.ttl.String(), func(t *testing.T) {
			e := newEnv(t)
			issued := e.c.Now()
			g1 := grant(t, issued, spec{id: gid(1), ttl: tc.ttl})
			e.listing(t, false, g1)
			e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1})
			// Present: just before, the statement given is the cached one.
			e.c.Add(tc.at - time.Second)
			p := mustPresent(t, e, gid(1))
			e.m.step(ctx)
			if n := e.f.count("leash.status.get"); n != 0 {
				t.Fatalf("refreshed %d times before the quarter", n)
			}
			st, _ := leashwire.ParseStatus(p.Status)
			if !st.IssuedAt.Equal(issued) {
				t.Fatalf("statement issued at %v, want the cached one of %v", st.IssuedAt, issued)
			}
			// At the refresh time the background loop refreshes it.
			e.c.Add(time.Second)
			e.m.step(ctx)
			if n := e.f.count("leash.status.get"); n != 1 {
				t.Fatalf("refreshed %d times at the quarter", n)
			}
			p = mustPresent(t, e, gid(1))
			st, _ = leashwire.ParseStatus(p.Status)
			if !st.IssuedAt.Equal(e.c.Now()) {
				t.Fatalf("presented the old statement after the refresh")
			}
			if n := e.f.count("leash.status.get"); n != 1 {
				t.Fatalf("refreshed again on presentation (%d)", n)
			}
		})
	}
}

// TestRefreshOnPresent: Present refreshes a statement due for refresh
// itself; a statement of the shortest lifetime (always within a minute
// of its end) is asked for at most once per minGap.
func TestRefreshOnPresent(t *testing.T) {
	e := newEnv(t)
	issued := e.c.Now()
	g1 := grant(t, issued, spec{id: gid(1), ttl: time.Minute})
	e.listing(t, false, g1)
	e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1})
	mustPresent(t, e, gid(1))
	mustPresent(t, e, gid(1))
	if n := e.f.count("leash.status.get"); n != 1 {
		t.Fatalf("%d refreshes within minGap", n)
	}
	e.c.Add(minGap)
	mustPresent(t, e, gid(1))
	if n := e.f.count("leash.status.get"); n != 2 {
		t.Fatalf("%d refreshes after minGap", n)
	}
	// A failing refresh presents nothing once the statement is due.
	e.c.Add(minGap)
	e.f.statusGet = func(string) *vaultconn.Response { return fail("internal") }
	refused(t, e, gid(1), ErrUnconfirmed)
}

// TestListedAtSessionStart: saved grants alone are never presented: the
// grants are listed first; a session start (device.session.granted)
// requires a new list, which the background loop sends.
func TestListedAtSessionStart(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.update(t, false, g1) // an event alone
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	if n := e.f.count("leash.grant.list"); n != 1 {
		t.Fatalf("%d lists before presenting", n)
	}

	// A new process with the saved grants: nothing until a list answers.
	saved := e.m.Snapshot()
	m2 := New(Options{Saved: saved, Now: e.c.Now})
	f2 := &fakeConn{m: m2, ik: pub(agentKey), access: pairing.Access{State: pairing.AccessActive}}
	if err := m2.Bind(f2); err != nil {
		t.Fatal(err)
	}
	f2.list = func() *vaultconn.Response { return fail("session_required") }
	if p, err := m2.Present(ctx, gid(1)); p != nil || !errors.Is(err, ErrNoSession) {
		t.Fatalf("saved grants presented: %v", err)
	}
	if len(m2.ConnectionInfo().Grants) != 1 || m2.ConnectionInfo().GrantsConfirmed {
		t.Errorf("info: %+v", m2.ConnectionInfo())
	}
	f2.list = func() *vaultconn.Response { return ok(set(t, false)) } // revoked meanwhile
	f2.setAccess(pairing.Access{State: pairing.AccessActive})
	if p, err := m2.Present(ctx, gid(1)); p != nil || !errors.Is(err, ErrNotGranted) {
		t.Fatalf("a grant revoked while stopped was presented: %v", err)
	}

	// A session start: the next step lists again before anything is
	// presented.
	e.m.Apply([]vaultconn.Message{{ID: "e2", Type: "device.session.granted", Body: json.RawMessage(`{}`)}})
	e.f.mu.Lock()
	e.f.list = nil // the list fails: nothing presented
	e.f.mu.Unlock()
	refused(t, e, gid(1), ErrUnconfirmed)
	e.listing(t, false, g1)
	e.c.Add(time.Minute)
	e.m.step(ctx)
	if n := e.f.count("leash.grant.list"); n < 3 {
		t.Fatalf("no list after the session start (%d)", n)
	}
	mustPresent(t, e, gid(1))
}

// TestNoSession: without an access session nothing is presented, and
// the background loop sends nothing.
func TestNoSession(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.f.setAccess(pairing.Access{State: pairing.AccessNone})
	refused(t, e, gid(1), ErrNoSession)
	e.f.setAccess(pairing.Access{State: pairing.AccessActive, SessionID: "s", ExpiresAt: now.Add(time.Minute)})
	e.c.Add(time.Minute)
	refused(t, e, gid(1), ErrNoSession)
	before := len(e.f.sent)
	e.c.Add(time.Hour)
	e.m.step(ctx)
	if len(e.f.sent) != before {
		t.Error("requests sent without a session")
	}
	// The session ended by event: listed again at the next start.
	e.f.setAccess(pairing.Access{State: pairing.AccessActive})
	e.m.Apply([]vaultconn.Message{{ID: "e3", Type: "device.session.ended", Body: json.RawMessage(`{}`)}})
	e.m.mu.Lock()
	listed := e.m.listed
	e.m.mu.Unlock()
	if listed {
		t.Error("still listed after the session ended")
	}
}

// TestMalformedSet: an update that does not parse presents nothing
// until a list parses again.
func TestMalformedSet(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	for _, body := range []string{`{"grants":[]}`, `{"suspended":false}`, `[]`, `{"grants":{},"suspended":false}`} {
		e.m.Apply([]vaultconn.Message{{ID: "e", Type: "leash.grant.updated", Body: json.RawMessage(body)}})
		e.f.mu.Lock()
		e.f.list = func() *vaultconn.Response { return ok(json.RawMessage(`{"grants":"x"}`)) }
		e.f.mu.Unlock()
		refused(t, e, gid(1), ErrUnconfirmed)
		e.listing(t, false, g1)
		mustPresent(t, e, gid(1))
	}
}

// TestGrantChecks: grants whose members disagree with their signed
// delegation, signed for another agent key or another device, signed
// under another key than their iss, or listed twice, are dropped; a
// grant without a delegation is shown but never presented.
func TestGrantChecks(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	bad := []json.RawMessage{
		grant(t, now, spec{id: gid(1), tamper: func(w map[string]any) { w["approval"] = "ask" }}),
		grant(t, now, spec{id: gid(2), tamper: func(w map[string]any) { w["per_hour"] = 61 }}),
		grant(t, now, spec{id: gid(3), tamper: func(w map[string]any) { w["version"] = 2 }}),
		grant(t, now, spec{id: gid(4), tamper: func(w map[string]any) { w["tags"] = []string{"other"} }}),
		grant(t, now, spec{id: gid(5), tamper: func(w map[string]any) { w["expires_at"] = now.Add(time.Hour).Format(time.RFC3339) }}),
		grant(t, now, spec{id: gid(6), sub: pub(otherKey)}),
		grant(t, now, spec{id: gid(7), agentID: "another-device"}),
		grant(t, now, spec{id: gid(8), tamper: func(w map[string]any) {
			sig := []byte(w["sig"].(string))
			sig[5] ^= 1
			w["sig"] = string(sig)
		}}),
		grant(t, now, spec{id: gid(9), tamper: func(w map[string]any) { w["grant_id"] = gid(10) }}),
	}
	dup := grant(t, now, spec{id: gid(11)})
	bare := grant(t, now, spec{id: gid(12), tamper: func(w map[string]any) {
		delete(w, "delegation")
		delete(w, "sig")
		delete(w, "status")
		delete(w, "status_sig")
	}})
	good := grant(t, now, spec{id: gid(13), scope: "message.send", approval: "ask", conns: []string{gid(20)}})
	e.listing(t, false, append(bad, dup, dup, bare, good)...)
	for i := 1; i <= 11; i++ {
		refused(t, e, gid(i), ErrNotGranted)
	}
	refused(t, e, gid(12), ErrNotPresentable)
	mustPresent(t, e, gid(13))
	var ids []string
	for _, gi := range e.m.ConnectionInfo().Grants {
		ids = append(ids, gi.GrantID)
	}
	if strings.Join(ids, ",") != gid(12)+","+gid(13) {
		t.Errorf("shown: %v", ids)
	}
}

// TestStatementChecks: a statement for another delegation, signed by
// another key, or not current is not used; the grant is presented after
// a refresh only.
func TestStatementChecks(t *testing.T) {
	for name, tamper := range map[string]func(t *testing.T, now time.Time, w map[string]any){
		"other delegation": func(t *testing.T, now time.Time, w map[string]any) {
			var o map[string]any
			_ = json.Unmarshal(grant(t, now, spec{id: gid(1), version: 2}), &o)
			w["status"], w["status_sig"] = o["status"], o["status_sig"]
		},
		"signed by the agent": func(t *testing.T, now time.Time, w map[string]any) {
			st, _ := json.Marshal(w["status"])
			var raw []byte
			_ = json.Unmarshal(st, &raw)
			sig, _ := leashwire.SignStatus(agentKey, raw)
			w["status_sig"] = sig
		},
		"stale": func(t *testing.T, now time.Time, w map[string]any) {
			var o map[string]any
			_ = json.Unmarshal(grant(t, now, spec{id: gid(1), statusAt: now.Add(-time.Hour)}), &o)
			w["status"], w["status_sig"] = o["status"], o["status_sig"]
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			now := e.c.Now()
			var g json.RawMessage
			g = grant(t, now, spec{id: gid(1), tamper: func(w map[string]any) { tamper(t, now, w) }})
			e.listing(t, false, g)
			e.f.statusGet = func(string) *vaultconn.Response { return fail("internal") }
			refused(t, e, gid(1), ErrUnconfirmed)
			e.c.Add(minGap)
			e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g})
			mustPresent(t, e, gid(1))
		})
	}
}

// TestHeld: owner_check_required stops refreshing until a vault.status
// that is not held shows the hold ended (neither a grant update nor a
// list answer ends it); internal/access is told; the background loop is
// woken when the hold ends.
func TestHeld(t *testing.T) {
	e := newEnv(t)
	var answered []string
	e.m.o.OnAnswer = func(code string, _ pairing.Access) { answered = append(answered, code) }
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.c.Add(700 * time.Second)
	e.f.statusGet = func(string) *vaultconn.Response { return fail("owner_check_required") }
	refused(t, e, gid(1), access.ErrOwnerCheck)
	n := e.f.count("leash.status.get")
	e.c.Add(10 * time.Minute)
	e.m.step(ctx)
	if e.f.count("leash.status.get") != n {
		t.Error("refreshed while held")
	}
	if strings.Join(answered, ",") != "owner_check_required" {
		t.Errorf("answers passed on: %v", answered)
	}
	if !e.m.Held() {
		t.Error("Held false while held")
	}
	// A grant update does not end the hold.
	e.update(t, false, g1)
	e.c.Add(10 * time.Minute)
	e.m.step(ctx)
	if !e.m.Held() || e.f.count("leash.status.get") != n || e.f.count("leash.grant.list") != 1 {
		t.Errorf("a grant update ended the hold: held %v, %d refreshes, %d lists", e.m.Held(), e.f.count("leash.status.get"), e.f.count("leash.grant.list"))
	}
	// Nor does the answer to a list (one sent before the hold can be
	// answered after it): the set is applied, the hold stays.
	e.listing(t, false, g1)
	if err := e.m.List(ctx); err != nil {
		t.Fatalf("List while held: %v", err)
	}
	if !e.m.Held() {
		t.Error("a list answer ended the hold")
	}
	e.c.Add(10 * time.Minute)
	e.m.step(ctx)
	if e.f.count("leash.status.get") != n || e.f.count("leash.grant.list") != 2 {
		t.Errorf("worked while held after a list: %d refreshes, %d lists", e.f.count("leash.status.get"), e.f.count("leash.grant.list"))
	}
	// Drain a wake-up left by the update or the list.
	select {
	case <-e.m.wake:
	default:
	}
	e.m.OnStatus("held")
	if !e.m.Held() {
		t.Error("vault.status held ended the hold")
	}
	e.m.OnStatus("ok")
	select {
	case <-e.m.wake:
	default:
		t.Error("the background loop was not woken when the hold ended")
	}
	if e.m.Held() {
		t.Error("Held true after the hold ended")
	}
	e.listing(t, false, g1)
	e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1})
	e.m.step(ctx)
	mustPresent(t, e, gid(1))
}

// TestSnapshot: the saved member holds the grants and suspended without
// statements, reads back the same, and is refused when altered.
func TestSnapshot(t *testing.T) {
	e := newEnv(t)
	if e.m.Snapshot() != nil {
		t.Fatal("snapshot before any grants")
	}
	now := e.c.Now()
	exp := now.Add(48 * time.Hour).Truncate(time.Second)
	g1, g2 := grant(t, now, spec{id: gid(1), exp: exp}), grant(t, now, spec{id: gid(2), scope: "message.send", approval: "ask", conns: []string{gid(20)}})
	e.listing(t, true, g2, g1)
	if err := e.m.List(ctx); err != nil {
		t.Fatal(err)
	}
	raw := e.m.Snapshot()
	for _, secretish := range []string{`"status"`, `"status_sig"`, `"rotations"`} {
		if bytes.Contains(raw, []byte(secretish)) {
			t.Errorf("saved member holds %s", secretish)
		}
	}
	s, err := ReadSaved(raw, testAgent, now)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Suspended || !s.AsOf.Equal(now) || len(s.Grants) != 2 || s.Grants[0].GrantID != gid(1) ||
		!s.Grants[0].ExpiresAt.Equal(exp) || s.Grants[0].PerHour != 60 || s.Grants[1].Connections[0] != gid(20) {
		t.Errorf("read back: %+v", s)
	}
	m2 := New(Options{Saved: raw, Now: e.c.Now})
	if err := m2.Bind(&fakeConn{m: m2, ik: pub(agentKey)}); err != nil {
		t.Fatal(err)
	}
	if got := m2.Snapshot(); !bytes.Equal(got, raw) {
		t.Errorf("reloaded snapshot differs:\n%s\n%s", got, raw)
	}
	if s, _ := ReadSaved(raw, testAgent, exp); len(s.Grants) != 1 {
		t.Errorf("expired grant shown: %+v", s.Grants)
	}
	if _, err := ReadSaved(raw, "", now); err == nil {
		t.Error("read without a device id")
	}
	if _, err := ReadSaved(raw, "another-device", now); err == nil {
		t.Error("read for another device")
	}
	for _, alt := range []string{
		strings.Replace(string(raw), `"v":1`, `"v":2`, 1),
		strings.Replace(string(raw), `"suspended"`, `"x":1,"suspended"`, 1),
		strings.Replace(string(raw), `"approval":"ask"`, `"approval":"auto"`, 1),
		string(raw) + " {}",
	} {
		if _, err := ReadSaved(json.RawMessage(alt), testAgent, now); err == nil {
			t.Errorf("altered member accepted: %s", alt)
		}
	}
	if s, err := ReadSaved(nil, testAgent, now); s != nil || err != nil {
		t.Error("nil member")
	}
}

// TestConnectionInfo: the data leash.connection_info returns.
func TestConnectionInfo(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	in := e.m.ConnectionInfo()
	if in.VaultID != "vault-1" || in.DeviceID != testAgent || in.Name != "test agent" || in.AccessSession != "active" ||
		in.GrantsConfirmed || in.GrantsAsOf != nil || len(in.Grants) != 0 {
		t.Errorf("before grants: %+v", in)
	}
	g1 := grant(t, now, spec{id: gid(1), scope: "message.send", approval: "ask", conns: []string{gid(20)}, exp: now.Add(time.Hour)})
	e.listing(t, false, g1)
	if err := e.m.List(ctx); err != nil {
		t.Fatal(err)
	}
	in = e.m.ConnectionInfo()
	if !in.GrantsConfirmed || in.Suspended || len(in.Grants) != 1 {
		t.Fatalf("info: %+v", in)
	}
	gi := in.Grants[0]
	if gi.GrantID != gid(1) || gi.Scope != "message.send" || gi.Approval != "ask" || gi.PerHour != 0 ||
		!gi.ExpiresAt.Equal(now.Add(time.Hour)) || gi.Connections[0] != gid(20) || gi.StatusUntil == nil {
		t.Errorf("grant: %+v", gi)
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, not := range []string{"delegation", "sig", "tags", "iss"} {
		if bytes.Contains(b, []byte(`"`+not+`"`)) {
			t.Errorf("info shows %s: %s", not, b)
		}
	}
	e.f.setAccess(pairing.Access{State: pairing.AccessNone})
	if in := e.m.ConnectionInfo(); in.AccessSession != "none" || in.GrantsConfirmed || in.Grants[0].StatusUntil != nil {
		t.Errorf("without a session: %+v", in)
	}
}

// TestRunLoop: Run lists after a session start and keeps statements
// fresh in the background, then stops with ctx.
func TestRunLoop(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1), noStatus: true})
	e.listing(t, false, g1)
	e.f.mu.Lock()
	e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1})
	e.f.mu.Unlock()
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.m.Run(rctx); close(done) }()
	e.m.Apply([]vaultconn.Message{{ID: "e", Type: "device.session.granted", Body: json.RawMessage(`{}`)}})
	deadline := time.Now().Add(10 * time.Second)
	for e.f.count("leash.grant.list") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no list")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A grant nobody asked to present is not refreshed in the background;
	// one that was is.
	time.Sleep(100 * time.Millisecond)
	if n := e.f.count("leash.status.get"); n != 0 {
		t.Fatalf("an unwanted statement refreshed (%d)", n)
	}
	e.m.mu.Lock()
	e.m.wanted[gid(1)] = e.c.Now()
	e.m.mu.Unlock()
	e.m.signal()
	for e.f.count("leash.status.get") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no list and refresh")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if e.f.count("leash.grant.list") != 1 {
		t.Errorf("%d lists", e.f.count("leash.grant.list"))
	}
	mustPresent(t, e, gid(1))
}
