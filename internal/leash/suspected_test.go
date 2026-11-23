package leash

import (
	"sync/atomic"
	"testing"
)

// After a resume or a clock jump, until the vault answers
// (internal/access Suspected): no grant is presented, connection info
// shows the access session as unknown and the grants as not confirmed,
// and the grants' work waits; once it has answered, all comes back.
func TestNothingWhileSuspected(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	if in := e.m.ConnectionInfo(); in.AccessSession != "active" || !in.GrantsConfirmed {
		t.Fatalf("before: %+v", in)
	}
	var suspect atomic.Bool
	e.m.SetSuspected(suspect.Load)
	suspect.Store(true)
	refused(t, e, gid(1), ErrNoSession)
	in := e.m.ConnectionInfo()
	if in.AccessSession != "unknown" || in.AccessSessionUntil != nil || in.GrantsConfirmed {
		t.Fatalf("while suspected: %+v", in)
	}
	lists := e.f.count("leash.grant.list")
	e.m.step(ctx)
	if e.f.count("leash.grant.list") != lists || e.f.count("leash.status.get") != 0 {
		t.Fatalf("the grants' work ran while suspected: %v", e.f.sent)
	}
	suspect.Store(false)
	mustPresent(t, e, gid(1))
	if in := e.m.ConnectionInfo(); in.AccessSession != "active" {
		t.Fatalf("after: %+v", in)
	}
}

// The grants' work held off for the suspicion starts at the status that
// ends it (OnStatus wakes the loop), not after the idle pause.
func TestSuspicionEndWakes(t *testing.T) {
	e := newEnv(t)
	var suspect atomic.Bool
	e.m.SetSuspected(suspect.Load)
	suspect.Store(true)
	e.m.step(ctx)
	select {
	case <-e.m.wake:
	default:
	}
	suspect.Store(false)
	e.m.OnStatus("ok")
	select {
	case <-e.m.wake:
	default:
		t.Fatal("the end of the suspicion did not wake the grants' work")
	}
	// A status with nothing held off wakes nothing.
	e.m.OnStatus("ok")
	select {
	case <-e.m.wake:
		t.Fatal("woken with nothing held off")
	default:
	}
}
