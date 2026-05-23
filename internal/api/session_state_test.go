package api

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSnapshot_ReturnsCurrentState pins the basic getter behavior so a
// future refactor of sessionState's storage doesn't silently drop a
// field.
func TestSnapshot_ReturnsCurrentState(t *testing.T) {
	s := &Server{
		sessionState: sessionState{
			ConnKey:         []byte("initial-key"),
			KeyID:           "conn-id-1",
			ConnectionID:    "conn-id-1",
			OwnerGUID:       "owner-1",
			Scope:           []string{"secrets.get"},
			ApprovalMode:    "always_ask",
			SessionID:       "sess-A",
			ExpiresAt:       1716000000,
			DurationSeconds: 3600,
		},
	}
	snap := s.Snapshot()
	if !bytes.Equal(snap.ConnKey, []byte("initial-key")) {
		t.Errorf("ConnKey = %q", snap.ConnKey)
	}
	if snap.SessionID != "sess-A" {
		t.Errorf("SessionID = %q", snap.SessionID)
	}
	if snap.ExpiresAt != 1716000000 {
		t.Errorf("ExpiresAt = %d", snap.ExpiresAt)
	}
	if snap.DurationSeconds != 3600 {
		t.Errorf("DurationSeconds = %d", snap.DurationSeconds)
	}
}

// TestRotateSession_SwapsRotatableFields verifies the field-by-field
// behavior of RotateSession — what changes, what doesn't.
//
// ConnectionID / KeyID / OwnerGUID must be preserved across rotation
// (the comment on RotateSession depends on this invariant; if a future
// refactor allows them to drift, every subsequent encrypted op the
// vault sees would mis-look-up the connection record).
func TestRotateSession_SwapsRotatableFields(t *testing.T) {
	s := &Server{
		sessionState: sessionState{
			ConnKey:         []byte("old-key"),
			KeyID:           "conn-id-1",
			ConnectionID:    "conn-id-1",
			OwnerGUID:       "owner-1",
			Scope:           []string{"secrets.get"},
			ApprovalMode:    "always_ask",
			SessionID:       "sess-A",
			ExpiresAt:       1716000000,
			DurationSeconds: 3600,
		},
	}

	s.RotateSession(
		[]byte("new-key"),
		[]string{"secrets.get", "secrets.put"},
		"auto_within_contract",
		"sess-B",
		1716010000,
		7200,
	)
	snap := s.Snapshot()

	// Rotatable fields: must change.
	if !bytes.Equal(snap.ConnKey, []byte("new-key")) {
		t.Errorf("ConnKey not rotated: %q", snap.ConnKey)
	}
	if len(snap.Scope) != 2 || snap.Scope[1] != "secrets.put" {
		t.Errorf("Scope not rotated: %v", snap.Scope)
	}
	if snap.ApprovalMode != "auto_within_contract" {
		t.Errorf("ApprovalMode not rotated: %q", snap.ApprovalMode)
	}
	if snap.SessionID != "sess-B" {
		t.Errorf("SessionID not rotated: %q", snap.SessionID)
	}
	if snap.ExpiresAt != 1716010000 {
		t.Errorf("ExpiresAt not rotated: %d", snap.ExpiresAt)
	}
	if snap.DurationSeconds != 7200 {
		t.Errorf("DurationSeconds not rotated: %d", snap.DurationSeconds)
	}

	// Identity fields: must be preserved.
	if snap.ConnectionID != "conn-id-1" {
		t.Errorf("ConnectionID changed: %q (should never change on extend)", snap.ConnectionID)
	}
	if snap.KeyID != "conn-id-1" {
		t.Errorf("KeyID changed: %q (should track ConnectionID)", snap.KeyID)
	}
	if snap.OwnerGUID != "owner-1" {
		t.Errorf("OwnerGUID changed: %q", snap.OwnerGUID)
	}
}

// TestRotateSession_ConcurrentReadsSafe is a race-detector bait: many
// concurrent Snapshot()s racing against a single RotateSession() must
// not produce torn reads. Run with `go test -race`.
//
// The assertion isn't on the values (which one wins is a race) — it's
// that the test completes without the race detector firing AND without
// any reader seeing a half-rotated state (some old fields + some new).
func TestRotateSession_ConcurrentReadsSafe(t *testing.T) {
	s := &Server{
		sessionState: sessionState{
			ConnKey:      []byte("key-A"),
			KeyID:        "conn-id-1",
			ConnectionID: "conn-id-1",
			Scope:        []string{"set-A"},
			SessionID:    "sess-A",
			ExpiresAt:    1000,
		},
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var tornReads atomic.Int64

	// 8 readers; each one repeatedly snapshots and checks
	// invariants. Coupling of fields: if Scope == ["set-A"] then
	// SessionID MUST be "sess-A" (they were written together). If
	// either differs from the matching pair, mark as torn.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					snap := s.Snapshot()
					okOld := (snap.SessionID == "sess-A" && len(snap.Scope) == 1 && snap.Scope[0] == "set-A")
					okNew := (snap.SessionID == "sess-B" && len(snap.Scope) == 1 && snap.Scope[0] == "set-B")
					if !okOld && !okNew {
						tornReads.Add(1)
					}
				}
			}
		}()
	}

	// One writer that rotates between two consistent states.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			select {
			case <-stop:
				return
			default:
				s.RotateSession(
					[]byte("key-B"),
					[]string{"set-B"},
					"always_ask",
					"sess-B",
					2000,
					3600,
				)
				time.Sleep(50 * time.Microsecond)
				s.RotateSession(
					[]byte("key-A"),
					[]string{"set-A"},
					"always_ask",
					"sess-A",
					1000,
					3600,
				)
				time.Sleep(50 * time.Microsecond)
			}
		}
	}()

	time.Sleep(100 * time.Millisecond)
	close(stop)
	wg.Wait()

	if torn := tornReads.Load(); torn > 0 {
		t.Errorf("%d torn reads — RotateSession isn't fully atomic from Snapshot's perspective", torn)
	}
}
