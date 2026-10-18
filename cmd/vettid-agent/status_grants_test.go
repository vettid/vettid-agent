package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/state"
)

func grantSet(deviceID string, suspended bool) []byte {
	g := map[string]any{"grant_id": "01JB2Z6V9K3M4N5P6Q7R8S9T41", "agent_id": deviceID, "version": 1,
		"scope": "message.send", "approval": "auto", "per_hour": 60, "per_day": 1000,
		"connections": []string{"01JB2Z6V9K3M4N5P6Q7R8S9T43"}, "status_ttl": 900,
		"expires_at": "2099-01-01T00:00:00Z", "issued_at": "2026-10-01T12:00:00Z"}
	b, _ := json.Marshal(map[string]any{"grants": []any{g}, "suspended": suspended})
	return b
}

// TestStatusShowsGrants: a leash.grant.updated received by `mcp` is saved
// and shown by `status` (scope, approval, limits, expiry, connections),
// with the suspension.
func TestStatusShowsGrants(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	withTestStatus(t)
	vw, err := state.ReadOnly(dir, statusResolve)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := pairing.DecodeRecord(vw.State)
	var dev struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(rec.Device, &dev)

	var out bytes.Buffer
	run([]string{"status", "--state-dir", dir}, &out, io.Discard)
	if !strings.Contains(out.String(), "Grants: none saved yet") {
		t.Errorf("before: %s", out.String())
	}

	if _, err := v.SendEvent("leash.grant.updated", grantSet(dev.DeviceID, true)); err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	withTestMCP(t, v, pr)
	done := make(chan int, 1)
	go func() { done <- run([]string{"mcp", "--state-dir", dir}, &bytes.Buffer{}, &bytes.Buffer{}) }()
	deadline := time.Now().Add(10 * time.Second)
	for v.Pending() != 0 || !strings.Contains(strings.Join(v.Received(), ","), "vault.status") {
		if time.Now().After(deadline) {
			t.Fatal("the event was not collected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	pw.Close()
	if rc := <-done; rc != 0 {
		t.Fatalf("mcp exit %d", rc)
	}
	out.Reset()
	if rc := run([]string{"status", "--state-dir", dir}, &out, io.Discard); rc != 0 {
		t.Fatalf("status exit %d", rc)
	}
	o := out.String()
	for _, w := range []string{"Grants: 1, as your vault sent them", "Paused by your vault",
		"message.send: allowed automatically, up to 60 an hour and 1000 a day without asking",
		"connections 01JB2Z6V9K3M4N5P6Q7R8S9T43", "(grant 01JB2Z6V9K3M4N5P6Q7R8S9T41)"} {
		if !strings.Contains(o, w) {
			t.Errorf("lacks %q:\n%s", w, o)
		}
	}
}

func TestWriteGrantsUnreadable(t *testing.T) {
	var out bytes.Buffer
	writeGrants(&out, json.RawMessage(`{"v":9}`), "d", time.Now())
	if !strings.Contains(out.String(), "cannot be read") {
		t.Errorf("%s", out.String())
	}
	if printable("a\x1b[31mb\n") != "a31mb" || printable("") != "-" {
		t.Error("printable")
	}
}
