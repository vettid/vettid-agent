//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
		{"resume automatic", pbtResumeAutomatic, "resumed from sleep: the access session is checked"},
		{"resume suspend", pbtResumeSuspend, "resumed from sleep: the access session is checked"},
		{"display state", pbtPowerSettingChange, "the display's state changed, perhaps for a standby: the access session is checked"},
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

// With no session running, a power event says so in its one line.
func TestPowerEventNoSession(t *testing.T) {
	h := &serviceHost{}
	var buf bytes.Buffer
	powerEvent(h, slog.New(slog.NewTextHandler(&buf, nil)),
		svc.ChangeRequest{Cmd: svc.PowerEvent, EventType: pbtPowerSettingChange})
	if !strings.Contains(buf.String(), "no session runs") || strings.Contains(buf.String(), "checked") ||
		strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("log = %q", buf.String())
	}
}

// When the registration fails, the failure is logged once and the session
// is made suspect every interval until the end function runs; when it
// succeeds, nothing is made suspect and its end function is returned.
func TestFollowDisplayRegistrationFails(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var n atomic.Int32
	m := access.New(noVault{}, 0, nil)
	end := followDisplay(context.Background(), logger,
		func() (func(), error) { return nil, errors.New("refused") },
		func() { n.Add(1); m.Suspect() }, 10*time.Millisecond)
	for deadline := time.Now().Add(5 * time.Second); n.Load() < 3; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("suspect called %d times in 5 s, want at least 3", n.Load())
		}
	}
	end()
	if !m.Suspected() {
		t.Fatal("not suspect")
	}
	after := n.Load()
	time.Sleep(50 * time.Millisecond)
	if n.Load() != after {
		t.Fatal("suspect still called after the end")
	}
	if c := strings.Count(buf.String(), "can't be followed"); c != 1 || strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("log = %q, want the failure once", buf.String())
	}
	if strings.Contains(buf.String(), "refused") {
		t.Fatalf("the error's own text was logged: %q", buf.String())
	}

	ended := false
	end = followDisplay(context.Background(), logger,
		func() (func(), error) { return func() { ended = true }, nil },
		func() { t.Error("suspect called with the registration in place") }, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	end()
	if !ended {
		t.Fatal("the registration's end function was not returned")
	}
}
