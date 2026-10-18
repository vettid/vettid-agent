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

// savedMember is a record's `leash` member with one grant (without a
// delegation) for device.
func savedMember(device string) json.RawMessage {
	g := map[string]any{"grant_id": "01JB2Z6V9K3M4N5P6Q7R8S9T41", "agent_id": device, "version": 1,
		"scope": "message.send", "approval": "auto", "per_hour": 60, "per_day": 1000,
		"connections": []string{"01JB2Z6V9K3M4N5P6Q7R8S9T43"}, "status_ttl": 900,
		"expires_at": "2099-01-01T00:00:00Z", "issued_at": "2026-10-01T12:00:00Z"}
	b, _ := json.Marshal(map[string]any{"v": 1, "as_of": "2026-10-17T12:00:00Z", "suspended": true, "grants": []any{g}})
	return b
}

// TestStatusShowsGrants: the grants saved in the state file are shown by
// `status` (scope, approval, limits, expiry, connections), with the
// suspension, and only for this device.
func TestStatusShowsGrants(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	withTestStatus(t)
	var out bytes.Buffer
	run([]string{"status", "--state-dir", dir}, &out, io.Discard)
	if !strings.Contains(out.String(), "Grants: none saved yet") {
		t.Errorf("before: %s", out.String())
	}

	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Load(statusResolve)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := pairing.DecodeRecord(raw)
	var dev struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(rec.Device, &dev)
	write := func(device string) {
		rec.Leash = savedMember(device)
		b, _ := rec.Encode()
		if err := s.Save(b); err != nil {
			t.Fatal(err)
		}
	}
	write(dev.DeviceID)
	s.Close()

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

	// Grants saved for another device are not shown.
	s, _ = state.Open(dir)
	if _, err := s.Load(statusResolve); err != nil {
		t.Fatal(err)
	}
	write("another-device")
	s.Close()
	out.Reset()
	run([]string{"status", "--state-dir", dir}, &out, io.Discard)
	if !strings.Contains(out.String(), "cannot be read") || strings.Contains(out.String(), "message.send") {
		t.Errorf("another device's grants: %s", out.String())
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
