//go:build windows

package run

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The access check is real, not vacuous: System32 grants this user read
// access (list the directory) but none of the rights that change it, and
// the user's own temporary directory grants those.
func TestAccessCheckIsReal(t *testing.T) {
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	sd, err := windows.GetNamedSecurityInfo(sys, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	g, err := maxAllowed(sd)
	if err != nil {
		t.Fatal(err)
	}
	const listDirectory = 0x0001
	if g&listDirectory == 0 {
		t.Fatalf("System32 grants %#x: no list right, so the check isn't working", g)
	}
	if g&dirRights != 0 {
		t.Fatalf("System32 grants %#x: a changing right (is the test running as an administrator?)", g)
	}
	if w, err := writable(t.TempDir(), false); err != nil || !w {
		t.Fatalf("own temporary directory: writable %v, %v", w, err)
	}
}

// A junction to a protected directory is refused: it's resolved by
// nothing before the check, and its owner could repoint it later.
func TestJunctionRunPathRefused(t *testing.T) {
	link := filepath.Join(t.TempDir(), "j")
	target := filepath.Join(os.Getenv("SystemRoot"), "System32")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("can't make a junction here: %v %s", err, out)
	}
	_, err := CheckRunPaths([]string{link})
	if err == nil || !strings.Contains(err.Error(), "junction") {
		t.Fatalf("junction to System32: %v", err)
	}
}

// A program extension after a stream name doesn't make a program.
func TestStreamNameIsNotAProgram(t *testing.T) {
	if _, err := Resolve(filepath.Join(t.TempDir(), "x.txt:s.exe"), nil); err == nil {
		t.Fatal("x.txt:s.exe accepted")
	}
}
