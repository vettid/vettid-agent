package leash

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/pairing"
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

// A session the vault named live while this computer's clock put its end
// in the past is shown and used as live, as tool calls use it; without
// the vault's word, the local clock decides.
func TestVaultNamedSessionShownAndUsed(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	g1 := grant(t, now, spec{id: gid(1)})
	e.listing(t, false, g1)
	mustPresent(t, e, gid(1))
	e.f.mu.Lock()
	e.f.access = pairing.Access{State: pairing.AccessActive, SessionID: "s1", ExpiresAt: now.Add(-time.Minute)}
	e.f.mu.Unlock()
	if in := e.m.ConnectionInfo(); in.AccessSession != "none" {
		t.Fatalf("by the local clock: %+v", in)
	}
	refused(t, e, gid(1), ErrNoSession)
	var named atomic.Bool
	named.Store(true)
	e.m.SetVaultNamed(func(a pairing.Access) bool { return named.Load() && a.SessionID == "s1" })
	in := e.m.ConnectionInfo()
	// Active, without an "until" this clock would show as already gone.
	if in.AccessSession != "active" || in.AccessSessionUntil != nil {
		t.Fatalf("by the vault's word: %+v", in)
	}
	mustPresent(t, e, gid(1))
	named.Store(false)
	if in := e.m.ConnectionInfo(); in.AccessSession != "none" {
		t.Fatalf("after the vault's word lapsed: %+v", in)
	}
}

// The grants' work runs for a session live by the vault's word, as tool
// calls use it.
func TestStepRunsOnVaultNamedSession(t *testing.T) {
	e := newEnv(t)
	now := e.c.Now()
	e.listing(t, false, grant(t, now, spec{id: gid(1)}))
	e.f.mu.Lock()
	e.f.access = pairing.Access{State: pairing.AccessActive, SessionID: "s1", ExpiresAt: now.Add(-time.Minute)}
	e.f.mu.Unlock()
	e.m.SetVaultNamed(func(a pairing.Access) bool { return a.SessionID == "s1" })
	e.m.mu.Lock()
	e.m.needList = true
	e.m.mu.Unlock()
	before := e.f.count("leash.grant.list")
	e.m.step(ctx)
	if e.f.count("leash.grant.list") == before {
		t.Fatal("the grants' work idled on a session live by the vault's word")
	}
}
