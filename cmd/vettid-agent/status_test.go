package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/state"
)

func withTestStatus(t *testing.T) {
	statusResolve = func(string) state.Protector { return cmdTestProtector{} }
	t.Cleanup(func() { statusResolve = nil })
}

// TestStatusPaired: status shows the pairing without secrets.
func TestStatusPaired(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	withTestStatus(t)
	var out, errOut bytes.Buffer
	if rc := run([]string{"status", "--state-dir", dir}, &out, &errOut); rc != 0 {
		t.Fatalf("exit %d: %s", rc, errOut.String())
	}
	o := out.String()
	for _, w := range []string{"Paired: yes", "Access session: none", `Paired: yes, as "Agent`, "Read without taking the state directory's lock"} {
		if !strings.Contains(o, w) {
			t.Errorf("lacks %q:\n%s", w, o)
		}
	}
	for _, secret := range []string{"seed", "token", "v4.public", "sessions"} {
		if strings.Contains(strings.ToLower(o), secret) {
			t.Errorf("output mentions %q:\n%s", secret, o)
		}
	}
}

// TestStatusWhileMCPRuns: status reads the state while `mcp` holds the
// lock, and `mcp` keeps it (a second mcp is still refused).
func TestStatusWhileMCPRuns(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	pr, pw := io.Pipe()
	withTestMCP(t, v, pr)
	withTestStatus(t)
	done := make(chan int, 1)
	go func() { done <- run([]string{"mcp", "--state-dir", dir}, &bytes.Buffer{}, &bytes.Buffer{}) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(strings.Join(v.Received(), ","), "vault.status") {
		if time.Now().After(deadline) {
			t.Fatal("mcp did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var out, errOut bytes.Buffer
	if rc := run([]string{"status", "--state-dir", dir}, &out, &errOut); rc != 0 || !strings.Contains(out.String(), "Paired: yes") {
		t.Fatalf("status: %d %s %s", rc, out.String(), errOut.String())
	}
	if _, err := state.Open(dir); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("the lock was lost: %v", err)
	}
	pw.Close()
	if rc := <-done; rc != 0 {
		t.Errorf("mcp exit %d", rc)
	}
}

func TestStatusNotPaired(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := filepath.Join(t.TempDir(), "absent")
	if rc := run([]string{"status", "--state-dir", dir}, &out, &errOut); rc != 0 || !strings.Contains(out.String(), "Not paired") {
		t.Errorf("exit %d: %s %s", rc, out.String(), errOut.String())
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("status created the directory")
	}
	if rc := run([]string{"status"}, &out, &errOut); rc != 2 {
		t.Errorf("no --state-dir: %d", rc)
	}
}

// TestStatusSanitizes: stored strings (name, device id, vault id) are
// shown without control or format characters.
func TestStatusSanitizes(t *testing.T) {
	withTestStatus(t)
	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	dev := `{"role":"agent","name":"evil\u001b[2J\nPaired: forged","device_id":"d\u202eevil","vault_id":"v\r\u200bx"}`
	rec := `{"v":1,"phase":"paired","device":` + dev + `,"access":{"state":"none"}}`
	if err := s.Create(cmdTestProtector{}, []byte(rec)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	var out, errOut bytes.Buffer
	if rc := run([]string{"status", "--state-dir", dir}, &out, &errOut); rc != 0 {
		t.Fatalf("exit %d: %s", rc, errOut.String())
	}
	o := out.String()
	if strings.ContainsAny(o, "\x1b\r\u202e\u200b") || strings.Count(o, "\nPaired:") != 1 {
		t.Errorf("unsanitized output:\n%q", o)
	}
	if !strings.Contains(o, `"evil[2JPaired: forged"`) {
		t.Errorf("name not shown cleaned:\n%s", o)
	}
}
