package leash

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// Messages arrive in no guaranteed order (VAULT-MESSAGING §8.4, §8.3):
// these tests deliver grant sets late and check that grant_seq
// (VAULT-MESSAGING §10.11; AGENT-PLAN §4.5, A3.5) keeps what the
// connector learned since from being undone.

func savedIDs(t *testing.T, e *env) []string {
	t.Helper()
	s, err := ReadSaved(e.m.Snapshot(), testAgent, e.c.Now())
	if err != nil {
		t.Fatal(err)
	}
	if s == nil {
		return nil
	}
	var ids []string
	for _, g := range s.Grants {
		ids = append(ids, g.GrantID)
	}
	return ids
}

func needsList(e *env) bool {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	return e.m.needList
}

// ownLate applies the answer, with this grant_seq, to a list this
// process sent with nothing learned outside the sets since, delivered
// after later messages.
func (e *env) ownLate(t *testing.T, seq uint64, suspended bool, grants ...json.RawMessage) {
	const id = "01JB2Z6V9K3M4N5P6Q7R8S9TXX"
	e.m.mu.Lock()
	e.m.lists[id] = e.m.gen
	e.m.mu.Unlock()
	e.m.Apply([]vaultconn.Message{{ID: nextULID(), Type: "leash.grant.list", Re: id, OK: true, Body: setN(t, seq, suspended, grants...)}})
}

// TestLateListAfterRevoke: a list answered before a revocation and
// delivered after it (a lower number) does not bring the revoked grant
// back, nor is it saved, whether this process sent the list or not; a
// list answered after the revocation holds.
func TestLateListAfterRevoke(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2, g3 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)}), grant(t, now, spec{id: gid(3)})
	e.listingN(t, 10, false, g1, g2)
	mustPresent(t, e, gid(1))
	e.updateN(t, 11, false, g2) // gid(1) revoked
	refused(t, e, gid(1), ErrNotGranted)

	e.ownLate(t, 10, false, g1, g2, g3)
	refused(t, e, gid(1), ErrNotGranted)
	refused(t, e, gid(3), ErrNotGranted)
	mustPresent(t, e, gid(2))
	e.otherList(t, 10, false, g1, g2)
	refused(t, e, gid(1), ErrNotGranted)
	if ids := savedIDs(t, e); len(ids) != 1 || ids[0] != gid(2) {
		t.Errorf("saved after the late lists: %v", ids)
	}
	if s := e.heldSeq(); s != 11 {
		t.Errorf("held number %d, want 11", s)
	}

	// A list answered now: what it says holds.
	e.listingN(t, 12, false, g2, g3)
	e.m.mu.Lock()
	e.m.needList = true
	e.m.mu.Unlock()
	e.m.step(ctx)
	mustPresent(t, e, gid(3))
	refused(t, e, gid(1), ErrNotGranted)
}

// TestHigherUpdateAdds: a leash.grant.updated with a higher number
// replaces the set, so it adds a grant, presentable without another list
// (the grants were listed in this session); one with a lower number
// changes nothing, whatever its id's time.
func TestHigherUpdateAdds(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.listingN(t, 20, false, g1)
	mustPresent(t, e, gid(1))
	lists := e.f.count("leash.grant.list")
	e.updateN(t, 21, false, g1, g2) // gid(2) issued
	mustPresent(t, e, gid(2))
	if n := e.f.count("leash.grant.list"); n != lists {
		t.Errorf("%d more lists after a higher update", n-lists)
	}
	if needsList(e) {
		t.Error("a list wanted after a higher update")
	}
	if ids := savedIDs(t, e); len(ids) != 2 {
		t.Errorf("saved: %v", ids)
	}

	e.updateN(t, 22, false, g2) // gid(1) revoked
	late, err := envelope.NewULID(now.Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	e.m.Apply([]vaultconn.Message{{ID: late, Type: "leash.grant.updated", Body: setN(t, 21, false, g1, g2)}})
	refused(t, e, gid(1), ErrNotGranted)
	mustPresent(t, e, gid(2))
}

// TestEqualKeepsSet: a set with the number held is the set already held:
// a grant it adds is not taken and one it lacks is not removed; only a
// fresher status statement is taken from it, and only one that binds the
// delegation held.
func TestEqualKeepsSet(t *testing.T) {
	e := newEnv(t)
	start := e.c.Now()
	g1 := grant(t, start, spec{id: gid(1)})
	g2 := grant(t, start, spec{id: gid(2)})
	e.listingN(t, 30, false, g1, g2)
	mustPresent(t, e, gid(1))
	mustPresent(t, e, gid(2))

	e.c.Add(700 * time.Second) // past the refresh time of a 900 s statement
	now := e.c.Now()
	// The same grant id and version with other delegation bytes: its
	// statement binds those, so it is not taken.
	other1 := grant(t, now, spec{id: gid(1)})
	e.updateN(t, 30, false, other1, g2)
	refused(t, e, gid(1), nil) // no status handler: a refresh fails

	fresh1 := grant(t, start, spec{id: gid(1), statusAt: now})
	g3 := grant(t, now, spec{id: gid(3)})
	e.updateN(t, 30, false, fresh1, g3) // gid(2) absent, gid(3) present
	// No status handler: Present must use the statement the set brought.
	mustPresent(t, e, gid(1))
	if n := e.f.count("leash.status.get"); n != 1 { // the refused one above
		t.Errorf("%d statement requests", n)
	}
	refused(t, e, gid(3), ErrNotGranted)
	if ids := savedIDs(t, e); len(ids) != 2 || ids[0] != gid(1) || ids[1] != gid(2) {
		t.Errorf("saved: %v", ids)
	}

	// An older statement, still current, does not replace a newer one.
	older1 := grant(t, start, spec{id: gid(1), statusAt: now.Add(-50 * time.Second)})
	e.updateN(t, 30, false, older1, g2)
	e.m.mu.Lock()
	st := e.m.statements[gid(1)]
	e.m.mu.Unlock()
	if st == nil || !st.issuedAt.Equal(now) {
		t.Error("an older statement replaced a newer one")
	}
}

// TestEqualListedOnlyByOwnList: at session start an equal number counts
// as listed only as the answer to this process's own list, never as an
// event or another's list.
func TestEqualListedOnlyByOwnList(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listingN(t, 40, false, g1)
	mustPresent(t, e, gid(1))
	e.m.Apply([]vaultconn.Message{{ID: nextULID(), Type: "device.session.granted", Body: json.RawMessage(`{}`)}})
	e.updateN(t, 40, false, g1)
	e.otherList(t, 40, false, g1)
	if in := e.m.ConnectionInfo(); in.GrantsConfirmed {
		t.Error("confirmed by an event or another's list")
	}
	mustPresent(t, e, gid(1)) // its own list
	if in := e.m.ConnectionInfo(); !in.GrantsConfirmed {
		t.Error("not confirmed by its own list")
	}
}

// TestListOvertaken: an update that arrives while List's own list is on
// its way (with a higher number) makes the answer older; List sends
// another, whose equal number confirms the set.
func TestListOvertaken(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	first := true
	e.f.list = func() *vaultconn.Response {
		if first {
			first = false
			e.updateN(t, 51, false, g2) // the revocation overtakes the answer
			return ok(setN(t, 50, false, g1, g2))
		}
		return ok(setN(t, 51, false, g2))
	}
	refused(t, e, gid(1), ErrNotGranted)
	if n := e.f.count("leash.grant.list"); n != 2 {
		t.Errorf("%d lists", n)
	}
	mustPresent(t, e, gid(2))
	if needsList(e) {
		t.Error("still wants a list")
	}
}

// TestNotFoundStaysDead: a grant answered not_found stays dead under an
// equal or higher number, by event or by a list sent before the
// not_found, until the answer to a list this process sent after it.
func TestNotFoundStaysDead(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.listingN(t, 60, false, g1, g2)
	mustPresent(t, e, gid(1))
	e.c.Add(700 * time.Second)
	e.f.statusGet = func(string) *vaultconn.Response { return fail("not_found") }
	refused(t, e, gid(1), ErrNotGranted)
	now = e.c.Now()
	g1, g2 = grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.updateN(t, 60, false, g1, g2)
	refused(t, e, gid(1), ErrNotGranted)
	e.updateN(t, 61, false, g1, g2)
	refused(t, e, gid(1), ErrNotGranted)
	e.staleList(t, 62, false, g1, g2)
	refused(t, e, gid(1), ErrNotGranted)
	if !needsList(e) {
		t.Error("no list wanted after a list sent before the not_found")
	}
	mustPresent(t, e, gid(2))
	e.listingN(t, 62, false, g1, g2)
	e.m.step(ctx)
	mustPresent(t, e, gid(1))
}

// TestForbiddenStaysSuspended: a suspension learned from forbidden holds
// under a higher number saying otherwise, by event or by a list sent
// before it, until the answer to a list sent after it.
func TestForbiddenStaysSuspended(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listingN(t, 70, false, g1)
	mustPresent(t, e, gid(1))
	e.c.Add(700 * time.Second)
	e.f.statusGet = func(string) *vaultconn.Response { return fail("forbidden") }
	refused(t, e, gid(1), ErrSuspended)
	now = e.c.Now()
	g1 = grant(t, now, spec{id: gid(1)})
	e.updateN(t, 71, false, g1)
	refused(t, e, gid(1), ErrSuspended)
	e.staleList(t, 72, false, g1)
	refused(t, e, gid(1), ErrSuspended)
	if s, _ := ReadSaved(e.m.Snapshot(), testAgent, e.c.Now()); !s.Suspended {
		t.Error("saved as resumed")
	}
	e.listingN(t, 72, false, g1)
	e.m.step(ctx)
	mustPresent(t, e, gid(1))
}

// TestSuspendResumeByNumber: suspension and resumption each take a new
// number; a late set from before the suspension does not end it, a
// resumption does.
func TestSuspendResumeByNumber(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listingN(t, 80, false, g1)
	mustPresent(t, e, gid(1))
	e.updateN(t, 81, true, grant(t, now, spec{id: gid(1), noStatus: true}))
	refused(t, e, gid(1), ErrSuspended)
	e.ownLate(t, 80, false, g1)
	e.updateN(t, 80, false, g1)
	refused(t, e, gid(1), ErrSuspended)
	e.updateN(t, 82, false, g1) // resumed
	mustPresent(t, e, gid(1))
}

// TestVersionNeverDecreases: a higher set carrying a grant in a lower
// version than held drops it and asks for a list.
func TestVersionNeverDecreases(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	v2 := grant(t, now, spec{id: gid(1), version: 2})
	v1 := grant(t, now, spec{id: gid(1), version: 1})
	e.listingN(t, 90, false, v2)
	p := mustPresent(t, e, gid(1))
	e.updateN(t, 91, false, v1)
	refused(t, e, gid(1), ErrNotGranted)
	if !needsList(e) {
		t.Error("no list wanted")
	}
	e.listingN(t, 92, false, v2)
	e.m.step(ctx)
	if q := mustPresent(t, e, gid(1)); string(q.Delegation) != string(p.Delegation) {
		t.Error("not the version 2 delegation")
	}
}

// TestUnknownNumber: with no number held (a new or re-paired state: the
// pairing batch never reaches this package, so its number is not
// recorded), an event or another's list only narrows and records
// nothing; this process's own list replaces the set and records its
// number, so an equal-numbered list then keeps a non-empty set.
func TestUnknownNumber(t *testing.T) {
	e := newEnv(t)
	if s := e.heldSeq(); s != 0 {
		t.Fatalf("a new state holds number %d", s)
	}
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.updateN(t, 100, false) // e.g. the pairing's empty set
	e.otherList(t, 101, false, g1)
	if s := e.heldSeq(); s != 0 {
		t.Errorf("an event recorded number %d", s)
	}
	if ids := savedIDs(t, e); len(ids) != 0 {
		t.Errorf("an event added grants: %v", ids)
	}
	// An own list older than an event seen is ignored.
	e.ownLate(t, 100, false, g1, g2)
	if s := e.heldSeq(); s != 0 {
		t.Errorf("an older own list recorded number %d", s)
	}
	e.listingN(t, 101, false, g1, g2)
	mustPresent(t, e, gid(1))
	if s := e.heldSeq(); s != 101 {
		t.Errorf("held number %d, want 101", s)
	}
	e.updateN(t, 101, false)
	mustPresent(t, e, gid(2))
}

// TestUnknownNumberNarrows: with no number held, an event removes grants
// it lacks (whatever its number) and the list it asks for restores the
// set.
func TestUnknownNumberNarrows(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	saved, err := encodeSaved([]*Grant{mustGrant(t, g1), mustGrant(t, g2)}, false, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	e = bindSaved(t, e, saved)
	e.updateN(t, 5, false, g2)
	if ids := savedIDs(t, e); len(ids) != 1 || ids[0] != gid(2) {
		t.Errorf("after the event: %v", ids)
	}
	if !needsList(e) {
		t.Error("no list wanted")
	}
	e.listingN(t, 6, false, g1, g2)
	mustPresent(t, e, gid(1))
}

func mustGrant(t *testing.T, raw json.RawMessage) *Grant {
	t.Helper()
	var w wireGrant
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	w.Status, w.StatusSig, w.Rotations = nil, nil, nil
	g, err := parseGrant(&w, testAgent)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// bindSaved returns a new env whose Manager starts from this saved member.
func bindSaved(t *testing.T, e *env, saved json.RawMessage) *env {
	t.Helper()
	m := New(Options{Saved: saved, Now: e.c.Now})
	f := &fakeConn{m: m, ik: pub(agentKey), access: pairing.Access{State: pairing.AccessActive}}
	if err := m.Bind(f); err != nil {
		t.Fatal(err)
	}
	return &env{c: e.c, f: f, m: m}
}

// TestSavedVersions: the `leash` member is saved at "v": 2 with the
// number; a "v": 1 member reads as number unknown, so only this
// process's own list widens its grants; a member of either version in
// the other's form is refused.
func TestSavedVersions(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.listingN(t, 110, false, g1)
	mustPresent(t, e, gid(1))
	var top map[string]json.RawMessage
	if err := json.Unmarshal(e.m.Snapshot(), &top); err != nil {
		t.Fatal(err)
	}
	if string(top["v"]) != "2" || string(top["grant_seq"]) != "110" {
		t.Errorf("saved v %s, grant_seq %s", top["v"], top["grant_seq"])
	}
	if e2 := bindSaved(t, e, e.m.Snapshot()); e2.heldSeq() != 110 {
		t.Errorf("reloaded number %d", e2.heldSeq())
	}

	v1 := strings.Replace(strings.Replace(string(e.m.Snapshot()), `"v":2`, `"v":1`, 1), `"grant_seq":110,`, "", 1)
	e1 := bindSaved(t, e, json.RawMessage(v1))
	if e1.heldSeq() != 0 {
		t.Fatalf("a v1 member read as number %d", e1.heldSeq())
	}
	if in := e1.m.ConnectionInfo(); len(in.Grants) != 1 {
		t.Fatalf("v1 grants not loaded: %+v", in)
	}
	e1.updateN(t, 999, false, g1, g2)
	if ids := savedIDs(t, e1); len(ids) != 1 {
		t.Errorf("an event widened a v1 state: %v", ids)
	}
	e1.listingN(t, 999, false, g1, g2)
	mustPresent(t, e1, gid(2))

	for _, bad := range []string{
		strings.Replace(string(e.m.Snapshot()), `"grant_seq":110,`, "", 1), // v2 without
		strings.Replace(v1, `"v":1,`, `"v":1,"grant_seq":3,`, 1),           // v1 with
	} {
		if _, err := decodeSaved(json.RawMessage(bad), testAgent); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TestWithoutSeq: a list or update without grant_seq, with 0, or with
// one that is not an unsigned 64-bit integer is ignored; the list counts
// as failed (paced from 15 s, doubling), tools answer vault_too_old, and
// it is logged once per session.
func TestWithoutSeq(t *testing.T) {
	for _, seq := range []string{"", `0`, `-1`, `1.5`, `"7"`, `null`, `18446744073709551616`, `true`} {
		e := newEnv(t)
		var logs bytes.Buffer
		e.m.log = slog.New(slog.NewTextHandler(&logs, nil))
		now := e.c.Now()
		g1 := grant(t, now, spec{id: gid(1)})
		body := `{"grants":[` + string(g1) + `],"suspended":false`
		if seq != "" {
			body += `,"grant_seq":` + seq
		}
		body += `}`
		e.f.list = func() *vaultconn.Response { return ok(json.RawMessage(body)) }
		refused(t, e, gid(1), ErrVaultTooOld)
		refused(t, e, gid(1), ErrVaultTooOld) // paced: not asked again yet
		if n := e.f.count("leash.grant.list"); n != 1 {
			t.Errorf("seq %s: %d lists before the pause ended", seq, n)
		}
		e.c.Add(minGap)
		refused(t, e, gid(1), ErrVaultTooOld)
		if n := e.f.count("leash.grant.list"); n != 2 {
			t.Errorf("seq %s: %d lists after 15 s", seq, n)
		}
		e.c.Add(minGap) // the second pause is 30 s
		refused(t, e, gid(1), ErrVaultTooOld)
		if n := e.f.count("leash.grant.list"); n != 2 {
			t.Errorf("seq %s: %d lists 15 s into a 30 s pause", seq, n)
		}
		if ids := savedIDs(t, e); len(ids) != 0 {
			t.Errorf("seq %s: saved %v", seq, ids)
		}
		if n := strings.Count(logs.String(), "too old"); n != 1 {
			t.Errorf("seq %s: logged %d times", seq, n)
		}

		// An update without a number removes nothing either.
		e.listingN(t, 120, false, g1)
		e.c.Add(retryMax)
		mustPresent(t, e, gid(1))
		e.m.Apply([]vaultconn.Message{{ID: nextULID(), Type: "leash.grant.updated", Body: json.RawMessage(strings.Replace(body, string(g1), "", 1))}})
		if ids := savedIDs(t, e); len(ids) != 1 {
			t.Errorf("seq %s: an update without a number changed the grants: %v", seq, ids)
		}
		// Logged again in a new session.
		e.m.Apply([]vaultconn.Message{{ID: nextULID(), Type: "device.session.granted", Body: json.RawMessage(`{}`)}})
		e.f.list = func() *vaultconn.Response { return ok(json.RawMessage(body)) }
		refused(t, e, gid(1), ErrVaultTooOld)
		if n := strings.Count(logs.String(), "too old"); n != 2 {
			t.Errorf("seq %s: logged %d times over two sessions", seq, n)
		}
	}
}

// TestFailedRefreshNoGrace: the 15 s during which a statement past its
// refresh time may still be presented count from the last successful
// refresh, so a failed one does not extend the old statement.
func TestFailedRefreshNoGrace(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.c.Add(675e9) // the refresh time of a 900 s statement
	e.f.statusGet = func(string) *vaultconn.Response { return fail("internal") }
	refused(t, e, gid(1), ErrUnconfirmed)
	e.c.Add(1e9)
	refused(t, e, gid(1), ErrUnconfirmed)
}

// TestBackgroundLoad: the background loop refreshes a 60 s statement
// (always due) at most once a minute, and only while the grant was
// asked for within wantedFor; then not at all.
func TestBackgroundLoad(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1), ttl: 60e9})
	e.listing(t, false, g1)
	e.f.statusGet = statusAnswer(t, e.c, map[string]json.RawMessage{gid(1): g1})
	mustPresent(t, e, gid(1)) // wanted; refreshed once on demand
	base := e.f.count("leash.status.get")
	for i := 0; i < 60; i++ { // 5 minutes in 5 s steps
		e.c.Add(5e9)
		e.m.step(ctx)
	}
	if n := e.f.count("leash.status.get") - base; n < 4 || n > 5 {
		t.Errorf("%d background refreshes in 5 minutes", n)
	}
	e.c.Add(wantedFor)
	base = e.f.count("leash.status.get")
	for i := 0; i < 60; i++ {
		e.c.Add(5e9)
		e.m.step(ctx)
	}
	if n := e.f.count("leash.status.get") - base; n != 0 {
		t.Errorf("%d refreshes for a grant no longer wanted", n)
	}
}

// TestBindNeedsDevice: without a device id nothing could be checked as
// this agent's, so Bind fails; and no grant parses without one.
func TestBindNeedsDevice(t *testing.T) {
	m := New(Options{})
	if err := m.Bind(&fakeConn{m: m, noDevice: true}); err == nil {
		t.Fatal("bound without a device id")
	}
	var w wireGrant
	e := newEnv(t)
	if err := json.Unmarshal(grant(t, e.c.Now(), spec{id: gid(1)}), &w); err != nil {
		t.Fatal(err)
	}
	if _, err := parseGrant(&w, ""); err == nil {
		t.Error("a grant parsed without a device id")
	}
}
