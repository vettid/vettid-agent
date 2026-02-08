package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRequestTracker_AddAndResolve(t *testing.T) {
	rt := NewRequestTracker(5 * time.Second)
	defer rt.Stop()

	ch := rt.Add("req-1", 0)

	result := &TrackedResult{
		Status:      StatusApproved,
		RequestID:   "req-1",
		SecretValue: "secret123",
		ExpiresAt:   "2026-02-08T17:00:00Z",
	}

	resolved := rt.Resolve("req-1", result)
	if !resolved {
		t.Fatal("expected Resolve to return true")
	}

	select {
	case got := <-ch:
		if got.Status != StatusApproved {
			t.Errorf("expected StatusApproved, got %s", got.Status)
		}
		if got.SecretValue != "secret123" {
			t.Errorf("expected secret value 'secret123', got %q", got.SecretValue)
		}
		if got.RequestID != "req-1" {
			t.Errorf("expected request ID 'req-1', got %q", got.RequestID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for result")
	}
}

func TestRequestTracker_ResolveUnknown(t *testing.T) {
	rt := NewRequestTracker(5 * time.Second)
	defer rt.Stop()

	resolved := rt.Resolve("unknown", &TrackedResult{Status: StatusApproved})
	if resolved {
		t.Error("expected Resolve to return false for unknown request")
	}
}

func TestRequestTracker_Timeout(t *testing.T) {
	// Use a very short timeout so the reaper fires quickly
	rt := NewRequestTracker(100 * time.Millisecond)
	defer rt.Stop()

	ch := rt.Add("req-timeout", 100*time.Millisecond)

	// Wait for the reaper to fire (reaper runs every 5s, so we test the channel directly)
	select {
	case got := <-ch:
		if got.Status != StatusTimeout {
			t.Errorf("expected StatusTimeout, got %s", got.Status)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for timeout result")
	}
}

func TestRequestTracker_Get(t *testing.T) {
	rt := NewRequestTracker(5 * time.Second)
	defer rt.Stop()

	rt.Add("req-get", 0)

	// Before resolve, Get returns nil (no result yet)
	got := rt.Get("req-get")
	if got != nil {
		t.Errorf("expected nil before resolve, got %+v", got)
	}

	// After resolve, Get returns the result
	rt.Resolve("req-get", &TrackedResult{
		Status:    StatusDenied,
		RequestID: "req-get",
		Reason:    "not in scope",
	})

	got = rt.Get("req-get")
	if got == nil {
		t.Fatal("expected result after resolve, got nil")
	}
	if got.Status != StatusDenied {
		t.Errorf("expected StatusDenied, got %s", got.Status)
	}
	if got.Reason != "not in scope" {
		t.Errorf("expected reason 'not in scope', got %q", got.Reason)
	}
}

func TestRequestTracker_GetUnknown(t *testing.T) {
	rt := NewRequestTracker(5 * time.Second)
	defer rt.Stop()

	got := rt.Get("nonexistent")
	if got != nil {
		t.Errorf("expected nil for unknown request, got %+v", got)
	}
}

func TestRequestTracker_PendingApproval(t *testing.T) {
	rt := NewRequestTracker(10 * time.Second)
	defer rt.Stop()

	ch1 := rt.Add("req-pending", 0)

	// First resolution: pending_approval
	rt.Resolve("req-pending", &TrackedResult{
		Status:    StatusPendingApproval,
		RequestID: "req-pending",
	})

	// The first waiter should receive pending_approval
	select {
	case got := <-ch1:
		if got.Status != StatusPendingApproval {
			t.Errorf("expected StatusPendingApproval, got %s", got.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pending_approval")
	}

	// Get should show pending_approval
	stored := rt.Get("req-pending")
	if stored == nil || stored.Status != StatusPendingApproval {
		t.Errorf("expected stored pending_approval, got %+v", stored)
	}

	// The entry should have a new channel for the final result.
	// We need to get it by accessing the tracker internals or by resolving again.
	// Resolve with final approval
	rt.Resolve("req-pending", &TrackedResult{
		Status:      StatusApproved,
		RequestID:   "req-pending",
		SecretValue: "final_secret",
	})

	// Check stored result
	final := rt.Get("req-pending")
	if final == nil || final.Status != StatusApproved {
		t.Errorf("expected stored approved, got %+v", final)
	}
}

func TestRequestTracker_WithResult(t *testing.T) {
	rt := NewRequestTracker(5 * time.Second)
	defer rt.Stop()

	ch := rt.Add("req-action", 0)

	resultData, _ := json.Marshal(map[string]any{
		"status_code": 200,
		"body":        `{"ok":true}`,
	})

	rt.Resolve("req-action", &TrackedResult{
		Status:    StatusCompleted,
		RequestID: "req-action",
		Result:    resultData,
	})

	select {
	case got := <-ch:
		if got.Status != StatusCompleted {
			t.Errorf("expected StatusCompleted, got %s", got.Status)
		}
		if got.Result == nil {
			t.Fatal("expected result data, got nil")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for action result")
	}
}
