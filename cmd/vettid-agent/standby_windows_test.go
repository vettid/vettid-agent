//go:build windows

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/sys/windows/svc"

	"github.com/vettid/vettid-agent/internal/access"
)

// Each power event that may follow a sleep or a standby makes the running
// session's access session suspect, with one log line; the event's data is
// never read (it is 0 here). Other power events do neither.
func TestPowerEventSuspectsSession(t *testing.T) {
	const pbtAPMPowerStatusChange = 0xA // the battery or AC state changed
	for _, c := range []struct {
		name string
		t    uint32
		want string // the log line's start, "" for none
	}{
		{"resume automatic", pbtResumeAutomatic, "resumed from sleep"},
		{"resume suspend", pbtResumeSuspend, "resumed from sleep"},
		{"display state", pbtPowerSettingChange, "the display's state changed"},
		{"power status", pbtAPMPowerStatusChange, ""},
	} {
		m := access.New(noVault{}, 0, nil)
		h := &serviceHost{mgr: m}
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		if m.Suspected() {
			t.Fatalf("%s: suspect before the event", c.name)
		}
		powerEvent(h, logger, svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: c.t})
		if got := m.Suspected(); got != (c.want != "") {
			t.Errorf("%s: suspect = %v, want %v", c.name, got, c.want != "")
		}
		if c.want == "" {
			if buf.Len() != 0 {
				t.Errorf("%s: logged %q", c.name, buf.String())
			}
			continue
		}
		if n := strings.Count(buf.String(), c.want); n != 1 || strings.Count(buf.String(), "\n") != 1 {
			t.Errorf("%s: log = %q, want one line with %q", c.name, buf.String(), c.want)
		}
	}
}

// With no session running, a power event changes nothing and does not fail.
func TestPowerEventNoSession(t *testing.T) {
	h := &serviceHost{}
	powerEvent(h, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: pbtPowerSettingChange})
}
