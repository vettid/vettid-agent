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
	// A file this user owns (and can change).
	p := filepath.Join(dir, "work.json")
	if err := os.WriteFile(p, []byte(pipeConfig("work")), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readPipeAt(p, "work")
	if !errors.Is(err, ErrNoService) || !strings.Contains(err.Error(), "not owned by Administrators or SYSTEM") {
		t.Fatalf("a file the member owns: %v", err)
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
	// The elevated administrator itself may change the file, and is
	// refused like anyone else who may.
	if _, err := readPipeAt(ok, "work"); !errors.Is(err, ErrNoService) {
		t.Fatalf("read by a user who can change it: %v", err)
	}
}
