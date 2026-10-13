//go:build windows

package ownerfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// allowedSIDs returns the SID of every access-allowed entry that
// applies to path itself, and whether the DACL is protected.
func allowedSIDs(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("DACL: %v (nil=%v)", err, dacl == nil)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce: %v", err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&inheritOnlyACE != 0 {
			continue
		}
		sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return sids, control&windows.SE_DACL_PROTECTED != 0
}

// grantEveryoneRead adds a read entry for Everyone (S-1-1-0).
func grantEveryoneRead(t *testing.T, path string) {
	t.Helper()
	out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(R)").CombinedOutput()
	if err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
}

func assertOnlyCurrentUser(t *testing.T, path string) {
	t.Helper()
	user, err := currentUserSID()
	if err != nil {
		t.Fatalf("currentUserSID: %v", err)
	}
	sids, protected := allowedSIDs(t, path)
	if !protected {
		t.Errorf("%s: DACL is not protected, so it still inherits from its parent", path)
	}
	if len(sids) != 1 || sids[0] != user.String() {
		t.Errorf("%s: allowed SIDs = %v, want only %s", path, sids, user.String())
	}
}

func TestWriteFile_NewFileGrantsOnlyCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("x")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	assertOnlyCurrentUser(t, path)
}

func TestWriteFile_TightensExistingLooseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	grantEveryoneRead(t, path)
	if err := Check(path); err == nil {
		t.Fatal("precondition: Check accepted a file readable by Everyone")
	}

	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	assertOnlyCurrentUser(t, path)
	if err := Check(path); err != nil {
		t.Errorf("Check after rewrite: %v", err)
	}
}

func TestCheck_RejectsEveryone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("x")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	grantEveryoneRead(t, path)
	if err := Check(path); err == nil {
		t.Error("Check accepted a file readable by Everyone")
	}
}

// A file made the ordinary way under the user profile inherits entries
// for the user, SYSTEM and Administrators. Check must accept that, or a
// token written by an earlier version would lock the agent out.
func TestCheck_AcceptsProfileInheritedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	if err := Check(path); err != nil {
		t.Errorf("Check on a profile-inherited file: %v", err)
	}
}

func TestMkdirAll_NewDirIsOwnerOnlyAndChildrenInherit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	assertOnlyCurrentUser(t, dir)

	// A file created without this package, e.g. the API socket.
	child := filepath.Join(dir, "child")
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	user, err := currentUserSID()
	if err != nil {
		t.Fatalf("currentUserSID: %v", err)
	}
	sids, _ := allowedSIDs(t, child)
	if len(sids) != 1 || sids[0] != user.String() {
		t.Errorf("child allowed SIDs = %v, want only %s", sids, user.String())
	}
}

func TestMkdirAll_LeavesExistingDirAlone(t *testing.T) {
	dir := t.TempDir()
	before, _ := allowedSIDs(t, dir)
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	after, _ := allowedSIDs(t, dir)
	if len(before) != len(after) {
		t.Errorf("MkdirAll changed an existing directory's DACL: %v -> %v", before, after)
	}
}
