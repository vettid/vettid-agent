//go:build linux || darwin

package run

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The child leads a session of its own and has no controlling terminal.
func TestStartGivesNoTerminal(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	code, out := runOutput(t, p, helperSpec(t, exe, "tty"))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var sid, pid int
	var tty string
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "sid=%d pid=%d tty=%s", &sid, &pid, &tty); err != nil {
		t.Fatalf("helper said %q: %v", out, err)
	}
	if sid != pid {
		t.Errorf("session %d, pid %d: not a session of its own", sid, pid)
	}
	if tty != "none" {
		t.Errorf("/dev/tty opened in the child")
	}
	if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		f.Close()
		t.Logf("this test has a terminal; the child had none")
	} else {
		t.Logf("this test has no terminal either, so only the session is a real check here")
	}
}

// A descriptor the connector holds without close-on-exec (as one its
// starter left open) doesn't reach the run.
func TestStartKeepsLeakedDescriptorsFromTheRun(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	leak := filepath.Join(t.TempDir(), "leak")
	if err := os.WriteFile(leak, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(leak, unix.O_RDONLY, 0) // no O_CLOEXEC
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatalf("test setup: flags %#x, %v", flags, err)
	}
	code, out := runOutput(t, p, helperSpec(t, exe, "fds", Var{"VETTID_RUN_TEST_LEAK", leak}))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := strings.TrimSpace(out); got != "clean" {
		t.Fatalf("child: %s", got)
	}
}
