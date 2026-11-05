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
// (Junctions need no privilege, so making one failing is a test failure.)
func TestJunctionRunPathRefused(t *testing.T) {
	link := filepath.Join(t.TempDir(), "j")
	target := os.Getenv("SystemRoot")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("can't make a junction: %v %s", err, out)
	}
	// At the leaf: the check names it.
	if _, err := CheckRunPaths([]string{link}); err == nil || !strings.Contains(err.Error(), "junction") {
		t.Errorf("junction at the leaf: %v", err)
	}
	// Under a junction (it as a parent): refused too, already when links
	// are resolved, which fails on a path through a junction.
	if _, err := CheckRunPaths([]string{filepath.Join(link, "System32")}); err == nil {
		t.Error("a path under a junction accepted")
	}
}

// A program extension after a stream name doesn't make a program.
// The stream exists, so it's the ":" rule that refuses it.
func TestStreamNameIsNotAProgram(t *testing.T) {
	file := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream := file + ":s.exe"
	if err := os.WriteFile(stream, []byte("MZ"), 0o600); err != nil {
		t.Fatalf("can't write a stream: %v", err)
	}
	if _, err := os.Stat(stream); err != nil {
		t.Fatalf("stream not there: %v", err)
	}
	if _, err := Resolve(stream, nil); err == nil {
		t.Fatal("x.txt:s.exe accepted")
	}
}
