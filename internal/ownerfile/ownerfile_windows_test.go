//go:build windows

package ownerfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sidEveryone = "*S-1-1-0"
	sidUsers    = "*S-1-5-32-545"
	sidSystem   = "*S-1-5-18"
	sidAdmins   = "*S-1-5-32-544"
)

func icacls(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("icacls", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls %v: %v: %s", args, err, out)
	}
}

func userSID(t *testing.T) string {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatalf("currentUserSID: %v", err)
	}
	return sid.String()
}

// security returns the owner SID, the SID of every access-allowed entry
// that applies to path itself, whether the DACL is protected, and the
// whole DACL in SDDL form.
func security(t *testing.T, path string) (owner string, allowed []string, protected bool, sddl string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatalf("Owner: %v", err)
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
		allowed = append(allowed, (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String())
	}
	return o.String(), allowed, control&windows.SE_DACL_PROTECTED != 0, sd.String()
}

func assertOnlyCurrentUser(t *testing.T, path string) {
	t.Helper()
	user := userSID(t)
	owner, allowed, protected, _ := security(t, path)
	if owner != user {
		t.Errorf("%s: owner = %s, want %s", path, owner, user)
	}
	if !protected {
		t.Errorf("%s: DACL is not protected, so it still inherits from its parent", path)
	}
	if len(allowed) != 1 || allowed[0] != user {
		t.Errorf("%s: allowed SIDs = %v, want only %s", path, allowed, user)
	}
}

func TestWriteFile_NewFileGrantsOnlyCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("x")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	assertOnlyCurrentUser(t, path)
}

func TestWriteFile_ReplacesExistingLooseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	icacls(t, path, "/grant", sidEveryone+":(F)")
	if err := Check(path); err == nil {
		t.Fatal("precondition: Check accepted a file open to Everyone")
	}

	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	assertOnlyCurrentUser(t, path)
	if err := Check(path); err != nil {
		t.Errorf("Check after rewrite: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

// The secret must not be written through a link that sits at the path.
// A hard link shares the target's data, so writing in place would put
// the secret in the other name too.
func TestWriteFile_DoesNotWriteThroughHardLink(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other")
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(other, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	if err := os.Link(other, path); err != nil {
		t.Skipf("cannot create a hard link here: %v", err)
	}

	if err := WriteFile(path, []byte("secret")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got, _ := os.ReadFile(other); string(got) != "untouched" {
		t.Errorf("the linked file now holds %q; the write went through the link", got)
	}
	if got, _ := os.ReadFile(path); string(got) != "secret" {
		t.Errorf("content = %q, want %q", got, "secret")
	}
}

// A reader that allows deletion (FILE_SHARE_DELETE), as antivirus and
// indexers do, does not stop the replace.
func TestWriteFile_ReplacesWhileOpenWithShareDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("old")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("CreateFile: %v", err)
	}
	defer windows.CloseHandle(h)

	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatalf("WriteFile while open: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

// A reader that does not allow deletion blocks the replace for as long
// as it holds the file. os.Open is such a reader. A short hold is
// ridden out by the retry.
func TestWriteFile_RetriesPastBriefReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("old")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	time.AfterFunc(80*time.Millisecond, func() { f.Close() })

	if err := WriteFile(path, []byte("new")); err != nil {
		t.Fatalf("WriteFile with a brief reader: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

// A reader that never lets go makes WriteFile fail. The previous file
// must survive, and no temp file may be left beside it.
func TestWriteFile_BlockedByReaderKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := WriteFile(path, []byte("old")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	if err := WriteFile(path, []byte("new")); err == nil {
		t.Fatal("WriteFile succeeded although the target was held open without delete sharing")
	}
	if got, _ := os.ReadFile(path); string(got) != "old" {
		t.Errorf("content = %q, want the previous %q", got, "old")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("a temp file was left behind: %d entries", len(entries))
	}
}

func TestWriteFile_LeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	for i := 0; i < 3; i++ {
		if err := WriteFile(path, []byte("x")); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "secret" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory holds %v, want only [secret]", names)
	}
}

// A failed write must not destroy the file that was there.
func TestWriteFile_FailureKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	// The target is a directory, so the final rename cannot succeed.
	path := filepath.Join(dir, "secret")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := WriteFile(path, []byte("x")); err == nil {
		t.Fatal("WriteFile over a directory returned nil")
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Errorf("the directory at the target is gone: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("a temp file was left behind: %d entries", len(entries))
	}
}

func TestCheck_RejectsOtherPrincipals(t *testing.T) {
	for name, sid := range map[string]string{"Everyone": sidEveryone, "Users": sidUsers} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := WriteFile(path, []byte("x")); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			icacls(t, path, "/grant", sid+":(R)")
			err := Check(path)
			if err == nil {
				t.Fatalf("Check accepted a file readable by %s", name)
			}
			if want := strings.TrimPrefix(sid, "*"); !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name %s", err, want)
			}
		})
	}
}

// A file made the ordinary way under a user profile has entries for
// the user, SYSTEM and Administrators. Check must accept that, or a
// token written by an earlier build would lock the agent out. The ACL
// is set explicitly so the test does not depend on where TEMP lives.
func TestCheck_AcceptsUserSystemAndAdministrators(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	icacls(t, path, "/inheritance:r",
		"/grant:r", "*"+userSID(t)+":(F)",
		"/grant:r", sidSystem+":(F)",
		"/grant:r", sidAdmins+":(F)")
	if err := Check(path); err != nil {
		t.Errorf("Check: %v", err)
	}
}

func TestCheck_IgnoresDenyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("x")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	icacls(t, path, "/deny", sidUsers+":(W)")
	if err := Check(path); err != nil {
		t.Errorf("Check rejected a file with only a deny entry added: %v", err)
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
	user := userSID(t)
	_, allowed, _, _ := security(t, child)
	if len(allowed) != 1 || allowed[0] != user {
		t.Errorf("child allowed SIDs = %v, want only %s", allowed, user)
	}
}

func TestMkdirAll_LeavesExistingDirAlone(t *testing.T) {
	dir := t.TempDir()
	_, _, _, before := security(t, dir)
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	_, _, _, after := security(t, dir)
	if before != after {
		t.Errorf("MkdirAll changed an existing directory's security:\n before %s\n after  %s", before, after)
	}
}

func TestMkdirAll_RejectsFileAtPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	if err := MkdirAll(path); err == nil {
		t.Error("MkdirAll accepted a regular file")
	}
}
