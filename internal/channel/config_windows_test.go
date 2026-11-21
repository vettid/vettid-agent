//go:build windows

package channel

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The configuration's folder comes from Windows, not from a variable the
// agent's MCP configuration could set.
func TestConfigPathIgnoresVariables(t *testing.T) {
	want, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	fake := t.TempDir()
	t.Setenv("ProgramData", fake)
	t.Setenv("ALLUSERSPROFILE", fake)
	got, err := ConfigPath("work")
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(want, "VettID", "agent", "work.json") {
		t.Fatalf("ConfigPath = %s", got)
	}
	for _, n := range []string{"", "..", `..\x`, "a/b", "Work"} {
		if _, err := ConfigPath(n); err == nil {
			t.Errorf("ConfigPath(%q) accepted", n)
		}
	}
}

func pipeConfig(n string) string {
	return `{"pipe":"vettid-agent-` + n + `-` + strings.Repeat("ab", 16) + `","run_path":["C:\\x"]}`
}

func TestReadPipeRefusals(t *testing.T) {
	dir := t.TempDir()
	if _, err := readPipeAt(filepath.Join(dir, "none.json"), "work"); !errors.Is(err, ErrNoService) {
		t.Fatalf("missing file: %v", err)
	}
	// A file this user made, and can change: refused, as owned by this
	// user, or (where an administrator's new files are owned by
	// Administrators) as one this user can change.
	p := filepath.Join(dir, "work.json")
	if err := os.WriteFile(p, []byte(pipeConfig("work")), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readPipeAt(p, "work")
	if !errors.Is(err, ErrNoService) ||
		!(strings.Contains(err.Error(), "not owned by Administrators or SYSTEM") || strings.Contains(err.Error(), "can be changed by ")) {
		t.Fatalf("a file this user can change: %v", err)
	}
}

// adminFile writes content to a file owned by Administrators, with the
// access list given (elevated only).
func adminFile(t *testing.T, content, dacl string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "work.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P" + dacl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	d, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, d, nil); err != nil {
		t.Fatal(err)
	}
	return p
}

// An administrator-owned file the member can only read is accepted; one
// the member may change, or naming another pairing's pipe, is not.
func TestReadPipeAdminOnly(t *testing.T) {
	member := newTestUser(t)
	m := member.sid.String()
	read := func(p, n string) (pipe string, err error) {
		member.as(t, func() { pipe, err = readPipeAt(p, n) })
		return
	}
	ok := adminFile(t, pipeConfig("work"), "(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;"+m+")")
	if pipe, err := read(ok, "work"); err != nil || pipe != "vettid-agent-work-"+strings.Repeat("ab", 16) {
		t.Fatalf("an administrator-only file: %q, %v", pipe, err)
	}
	if _, err := read(ok, "other"); !errors.Is(err, ErrNoService) {
		t.Fatalf("another pairing's pipe: %v", err)
	}
	for _, ace := range []string{"(A;;FW;;;" + m + ")", "(A;;0x10000;;;" + m + ")", "(A;;FW;;;BU)", "(A;;WD;;;WD)"} {
		p := adminFile(t, pipeConfig("work"), "(A;;FA;;;BA)(A;;FR;;;"+m+")"+ace)
		if _, err := read(p, "work"); !errors.Is(err, ErrNoService) || !strings.Contains(err.Error(), "can be changed") {
			t.Fatalf("with %s: %v", ace, err)
		}
	}
	// An elevated administrator (this test) reads the same file the same
	// way: the check is of the file, not of who reads it.
	if pipe, err := readPipeAt(ok, "work"); err != nil || pipe == "" {
		t.Fatalf("read by an elevated administrator: %q, %v", pipe, err)
	}
}

// adminOnly judges the descriptor alone: the same answer whoever reads.
func TestAdminOnly(t *testing.T) {
	const m = "S-1-5-21-1-2-3-1001" // a member
	ti := ServiceSID("TrustedInstaller")
	for _, c := range []struct {
		sddl string
		ok   bool
	}{
		{"O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;" + m + ")", true},
		{"O:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)", true},
		{"O:BAD:P(A;;FA;;;" + ti + ")(A;;FR;;;WD)", true},
		{"O:BAD:P(A;;FA;;;BA)(D;;FA;;;" + m + ")", true},       // a deny takes away
		{"O:BAD:P(A;;FA;;;BA)(A;OICIIO;FA;;;" + m + ")", true}, // inherit-only: not for this file
		{"O:BAD:P(A;;FA;;;BA)(A;;0x1200a9;;;" + m + ")", true}, // read and execute
		{"O:" + m + "D:P(A;;FA;;;BA)", false},                  // owned by the member
		{"O:BUD:P(A;;FA;;;BA)", false},                         // owned by Users
		{"O:BAD:P(A;;FA;;;BA)(A;;FW;;;" + m + ")", false},      // write
		{"O:BAD:P(A;;FA;;;BA)(A;;0x4;;;" + m + ")", false},     // append
		{"O:BAD:P(A;;FA;;;BA)(A;;0x10000;;;" + m + ")", false}, // delete
		{"O:BAD:P(A;;FA;;;BA)(A;;WD;;;" + m + ")", false},      // change the access
		{"O:BAD:P(A;;FA;;;BA)(A;;WO;;;" + m + ")", false},      // change the owner
		{"O:BAD:P(A;;FA;;;BA)(A;;GW;;;" + m + ")", false},      // generic write
		{"O:BAD:P(A;;FA;;;BA)(A;;GA;;;BU)", false},             // generic all, Users
		{"O:BAD:P(A;;FA;;;BA)(A;;0x100;;;AU)", false},          // attributes, Authenticated Users
		{"O:BAD:P(A;;FA;;;BA)(A;;FA;;;OW)", false},             // OWNER RIGHTS: not on the list
		{"O:BAD:P(A;;FA;;;BA)(A;;FA;;;CO)", false},             // CREATOR OWNER, effective
		{"O:BAD:", true}, // an empty access list: nobody but the owner
		{"O:BA", false},  // no DACL: anyone
		{"O:BAD:P(A;;FA;;;BA)(XA;;FW;;;" + m + ";(WIN://x))", false}, // a callback entry
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.sddl, err)
		}
		err = adminOnly(sd)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok %v", c.sddl, err, c.ok)
		}
	}
}
