package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/pairing/pairtest"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// pairedDir pairs through `vettid-agent pair` and returns the state
// directory.
func pairedDir(t *testing.T, v *pairtest.Vault) string {
	t.Helper()
	code, err := v.Code(invite.KindAgent, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "state")
	withTestPairing(t, v, "")
	var errOut bytes.Buffer
	if rc := run([]string{"pair", "--state-dir", dir, code}, &bytes.Buffer{}, &errOut); rc != 0 {
		t.Fatalf("pair: %d %s", rc, errOut.String())
	}
	return dir
}

func withTestMCP(t *testing.T, v *pairtest.Vault, stdin io.Reader) {
	t.Helper()
	mcpIn = stdin
	mcpResolve = func(string) state.Protector { return cmdTestProtector{} }
	mcpOptions = func(o *vaultconn.Options) {
		o.HTTP = v.HTTPClient()
		o.PollWait = 10 * time.Millisecond
	}
	t.Cleanup(func() { mcpIn, mcpResolve, mcpOptions = os.Stdin, nil, nil })
}

// TestMCPExitsOnEOF: `mcp` connects, and exits 0 when standard input
// closes; it writes nothing to standard output.
func TestMCPExitsOnEOF(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	pr, pw := io.Pipe()
	withTestMCP(t, v, pr)
	done := make(chan int, 1)
	var out, errOut bytes.Buffer
	go func() { done <- run([]string{"mcp", "--state-dir", dir}, &out, &errOut) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(strings.Join(v.Received(), ","), "vault.status") {
		if time.Now().After(deadline) {
			t.Fatal("no vault.status")
		}
		time.Sleep(10 * time.Millisecond)
	}
	pw.Close()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("exit %d: %s", rc, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mcp did not exit on EOF")
	}
	if out.Len() != 0 {
		t.Errorf("wrote to standard output: %q", out.String())
	}
}

// TestMCPUnlinked: device.unlinked wipes the state and `mcp` exits 1
// with the AG12 text; standard output stays empty.
func TestMCPUnlinked(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	if _, err := v.SendEvent("device.unlinked", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	defer pw.Close()
	withTestMCP(t, v, pr)
	var out, errOut bytes.Buffer
	if rc := run([]string{"mcp", "--state-dir", dir}, &out, &errOut); rc != 1 {
		t.Fatalf("exit %d: %s", rc, errOut.String())
	}
	if !strings.Contains(errOut.String(), vaultconn.TextUnlinked) || out.Len() != 0 {
		t.Errorf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, state.StateFileName)); !os.IsNotExist(err) {
		t.Error("state file kept")
	}
}

func TestMCPNotPaired(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := run([]string{"mcp", "--state-dir", filepath.Join(t.TempDir(), "s")}, &out, &errOut); rc != 1 || !strings.Contains(errOut.String(), "not paired") || out.Len() != 0 {
		t.Errorf("exit %d stdout %q stderr %q", rc, out.String(), errOut.String())
	}
	if rc := run([]string{"mcp"}, &out, &errOut); rc != 2 {
		t.Errorf("no --state-dir: exit %d", rc)
	}
}
