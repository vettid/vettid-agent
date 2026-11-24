//go:build windows

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/vettid/vettid-agent/internal/access"
)

// displaySetting is a POWERBROADCAST_SETTING with a DWORD value, as
// Windows sends for GUID_CONSOLE_DISPLAY_STATE.
type displaySetting struct {
	Setting    windows.GUID
	DataLength uint32
	Value      uint32
}

func displayEvent(v uint32) *displaySetting {
	return &displaySetting{Setting: guidConsoleDisplayState, DataLength: 4, Value: v}
}

func TestDisplayWatch(t *testing.T) {
	const dimmed = 2
	other := windows.GUID{Data1: 1}
	steps := []struct {
		name string
		t    uint32
		s    *displaySetting
		want bool
	}{
		{"on at registration", pbtPowerSettingChange, displayEvent(displayOn), false},
		{"dimmed", pbtPowerSettingChange, displayEvent(dimmed), false},
		{"on after dimmed", pbtPowerSettingChange, displayEvent(displayOn), false},
		{"off", pbtPowerSettingChange, displayEvent(displayOff), false},
		{"another setting", pbtPowerSettingChange, &displaySetting{Setting: other, DataLength: 4, Value: displayOn}, false},
		{"too short", pbtPowerSettingChange, &displaySetting{Setting: guidConsoleDisplayState, DataLength: 1, Value: displayOn}, false},
		{"another event", pbtResumeAutomatic, displayEvent(displayOn), false},
		{"no data", pbtPowerSettingChange, nil, false},
		{"on after off", pbtPowerSettingChange, displayEvent(displayOn), true},
		{"on again", pbtPowerSettingChange, displayEvent(displayOn), false},
		{"off again", pbtPowerSettingChange, displayEvent(displayOff), false},
		{"dimmed while off", pbtPowerSettingChange, displayEvent(dimmed), false},
		{"on after off and dimmed", pbtPowerSettingChange, displayEvent(displayOn), true},
	}
	var w displayWatch
	for _, s := range steps {
		var p unsafe.Pointer
		if s.s != nil {
			p = unsafe.Pointer(s.s)
		}
		if got := w.event(s.t, p); got != s.want {
			t.Errorf("%s: event = %v, want %v", s.name, got, s.want)
		}
	}
}

// changeRequest is the power event the service manager hands Execute,
// with data s.
func changeRequest(t uint32, s *displaySetting) svc.ChangeRequest {
	c := svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: t}
	if s != nil {
		c.EventData = uintptr(unsafe.Pointer(s))
	}
	return c
}

// The display coming on after it was off makes the running session's
// access session suspect, and says so in one log line; the display going
// off, or on with no off before it, does not.
func TestPowerEventDisplaySuspectsSession(t *testing.T) {
	m := access.New(noVault{}, 0, nil)
	h := &serviceHost{mgr: m}
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var display displayWatch
	on, off := displayEvent(displayOn), displayEvent(displayOff)

	powerEvent(h, &display, logger, changeRequest(pbtPowerSettingChange, on))
	powerEvent(h, &display, logger, changeRequest(pbtPowerSettingChange, off))
	if m.Suspected() {
		t.Fatal("suspect before the display came on again")
	}
	if buf.Len() != 0 {
		t.Fatalf("logged before the display came on again: %q", buf.String())
	}
	powerEvent(h, &display, logger, changeRequest(pbtPowerSettingChange, on))
	if !m.Suspected() {
		t.Fatal("not suspect after the display came on after it was off")
	}
	if n := strings.Count(buf.String(), "the display came on"); n != 1 {
		t.Fatalf("logged %d display lines, want 1: %q", n, buf.String())
	}
}

// The resume events still make the session suspect.
func TestPowerEventResumeSuspectsSession(t *testing.T) {
	for _, e := range []uint32{pbtResumeAutomatic, pbtResumeSuspend} {
		m := access.New(noVault{}, 0, nil)
		h := &serviceHost{mgr: m}
		var buf bytes.Buffer
		var display displayWatch
		powerEvent(h, &display, slog.New(slog.NewTextHandler(&buf, nil)), changeRequest(e, nil))
		if !m.Suspected() {
			t.Errorf("event %#x: not suspect", e)
		}
		if !strings.Contains(buf.String(), "resumed from sleep") {
			t.Errorf("event %#x: no log line: %q", e, buf.String())
		}
	}
}
