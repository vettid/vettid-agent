package leash

import (
	"encoding/json"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"

	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// Messages arrive in no guaranteed order (VAULT-MESSAGING §8.4, §8.3):
// these tests deliver grant sets late and check that what the connector
// learned since is never undone.

func savedIDs(t *testing.T, e *env) []string {
	t.Helper()
	s, err := ReadSaved(e.m.Snapshot(), testAgent, e.c.Now())
	if err != nil {
		t.Fatal(err)
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

// TestLateListAfterRevoke: a list answer sent before a revocation and
// delivered after it does not bring the revoked grant back (nor is it
// saved); an answer to a list this process did not send cannot either; a
// list sent after the revocation restores the grants correctly.
func TestLateListAfterRevoke(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2, g3 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)}), grant(t, now, spec{id: gid(3)})
	e.listing(t, false, g1, g2)
	mustPresent(t, e, gid(1))
	e.update(t, false, g2) // gid(1) revoked
	refused(t, e, gid(1), ErrNotGranted)

	e.staleList(t, false, g1, g2, g3)
	refused(t, e, gid(1), ErrNotGranted)
	refused(t, e, gid(3), ErrNotGranted) // a late answer adds nothing
	mustPresent(t, e, gid(2))
	if ids := savedIDs(t, e); len(ids) != 1 || ids[0] != gid(2) {
		t.Errorf("saved after the late list: %v", ids)
	}
	if !needsList(e) {
		t.Error("no fresh list wanted after a late answer")
	}
	// An answer to a list someone else sent (internal/access's check).
	e.m.Apply([]vaultconn.Message{{ID: nextULID(), Type: "leash.grant.list", Re: "01JB2Z6V9K3M4N5P6Q7R8S9TYY", OK: true, Body: set(t, false, g1, g2)}})
	refused(t, e, gid(1), ErrNotGranted)

	// A list sent now: what it says holds.
	e.listing(t, false, g2, g3)
	e.m.step(ctx)
	mustPresent(t, e, gid(3))
	refused(t, e, gid(1), ErrNotGranted)
}

// TestListOvertaken: an update that arrives while List's own list is on
// its way makes List send another; the first answer only narrows.
func TestListOvertaken(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	first := true
	e.f.list = func() *vaultconn.Response {
		if first {
			first = false
			e.update(t, false, g2) // the revocation overtakes the answer
			return ok(set(t, false, g1, g2))
		}
		return ok(set(t, false, g2))
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

// TestLateListAfterSuspend: a late list saying not suspended does not end
// a suspension; neither does an update; a list sent after it does, and
// the background loop sends one while suspended.
func TestLateListAfterSuspend(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.update(t, true, grant(t, now, spec{id: gid(1), noStatus: true}))
	refused(t, e, gid(1), ErrSuspended)
	e.staleList(t, false, g1)
	refused(t, e, gid(1), ErrSuspended)
	e.update(t, false, g1)
	refused(t, e, gid(1), ErrSuspended)
	if s, _ := ReadSaved(e.m.Snapshot(), testAgent, e.c.Now()); !s.Suspended {
		t.Error("saved as resumed")
	}
	e.listing(t, false, g1)
	e.m.step(ctx)
	mustPresent(t, e, gid(1))
}

// TestNotFoundThenLateSet: a grant answered not_found stays unusable
// whatever set arrives later, until a list sent after the not_found
// lists it.
func TestNotFoundThenLateSet(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.listing(t, false, g1, g2)
	mustPresent(t, e, gid(1))
	e.c.Add(700e9)
	e.f.statusGet = func(string) *vaultconn.Response { return fail("not_found") }
	refused(t, e, gid(1), ErrNotGranted)
	now = e.c.Now()
	g1, g2 = grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	e.update(t, false, g1, g2)
	refused(t, e, gid(1), ErrNotGranted)
	e.staleList(t, false, g1, g2)
	refused(t, e, gid(1), ErrNotGranted)
	e.listing(t, false, g1, g2)
	e.m.step(ctx)
	mustPresent(t, e, gid(1))
}

// TestVersionNeverDecreases: a set carrying a grant in a lower version
// than held drops it (the newer delegation is not replaced by the older
// one); a narrowing set with another version removes it.
func TestVersionNeverDecreases(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	v2 := grant(t, now, spec{id: gid(1), version: 2})
	v1 := grant(t, now, spec{id: gid(1), version: 1})
	e.listing(t, false, v2)
	p := mustPresent(t, e, gid(1))
	e.update(t, false, v1)
	refused(t, e, gid(1), ErrNotGranted)
	if !needsList(e) {
		t.Error("no list wanted")
	}
	e.listing(t, false, v2)
	e.m.step(ctx)
	if q := mustPresent(t, e, gid(1)); string(q.Delegation) != string(p.Delegation) {
		t.Error("not the version 2 delegation")
	}
	e.staleList(t, false, v1)
	refused(t, e, gid(1), ErrNotGranted)
}

// TestOlderUpdateNarrows: an update older (by the vault's clock) than a
// set already applied only narrows: it adds no grant.
func TestOlderUpdateNarrows(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1, g2 := grant(t, now, spec{id: gid(1)}), grant(t, now, spec{id: gid(2)})
	old, err := envelope.NewULID(now.Add(-24 * 3600e9))
	if err != nil {
		t.Fatal(err)
	}
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.update(t, false, g1)
	e.m.Apply([]vaultconn.Message{{ID: old, Type: "leash.grant.updated", Body: set(t, false, g2)}})
	refused(t, e, gid(2), ErrNotGranted)
	refused(t, e, gid(1), ErrNotGranted) // absent from it: removed
	e.m.Apply([]vaultconn.Message{{ID: "not-a-ulid", Type: "leash.grant.updated", Body: json.RawMessage(set(t, false, g1, g2))}})
	refused(t, e, gid(2), ErrNotGranted)
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
