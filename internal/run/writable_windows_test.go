//go:build windows

package run

import (
	"os"
	"path/filepath"
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
