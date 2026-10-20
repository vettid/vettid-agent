//go:build windows

package state

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	sidEveryone = "S-1-1-0"
	sidUsers    = "S-1-5-32-545"
	sidSystem   = "S-1-5-18"
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
		t.Fatal(err)
	}
	return sid.String()
}

// assertOwnerOnly checks that path is owned by the current user and has
// a protected DACL with one entry, for the current user.
func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user := userSID(t)
	owner, _, err := sd.Owner()
	if err != nil || owner.String() != user {
		t.Errorf("%s: owner %v, want %s", path, owner, user)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("%s: DACL not protected (inherits from the parent)", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s: no DACL", path)
	}
	if dacl.AceCount != 1 {
		t.Errorf("%s: %d entries, want 1 (%s)", path, dacl.AceCount, sd.String())
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || sid != user {
		t.Errorf("%s: entry type %d for %s, want an allow entry for %s", path, ace.Header.AceType, sid, user)
	}
}

func TestOwnerOnlyDACLOnCreate(t *testing.T) {
	s := openTest(t)
	if err := s.Create(newFixedProtector(seq(0x40, 32)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("y")); err != nil {
		t.Fatal(err)
	}
	assertOwnerOnly(t, s.Dir())
	assertOwnerOnly(t, s.Path())
	assertOwnerOnly(t, filepath.Join(s.Dir(), LockFileName))
}

func TestLoadRefusesDACLGrantingOthers(t *testing.T) {
	for _, sid := range []string{sidEveryone, sidUsers, sidSystem} {
		t.Run(sid, func(t *testing.T) {
			s := openTest(t)
			p := newFixedProtector(seq(0x40, 32))
			if err := s.Create(p, []byte("x")); err != nil {
				t.Fatal(err)
			}
			icacls(t, s.Path(), "/grant", "*"+sid+":(R)")
			_, err := s.Load(resolverFor(p))
			if !errors.Is(err, ErrNotOwnerOnly) {
				t.Fatalf("Load = %v, want ErrNotOwnerOnly", err)
			}
			if !strings.Contains(err.Error(), sid) {
				t.Errorf("error %q does not name %s", err, sid)
			}
		})
	}
}

func TestRefusesDirectoryDACLGrantingOthers(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	icacls(t, s.Dir(), "/grant", "*"+sidUsers+":(OI)(CI)(R)")
	if _, err := s.Load(resolverFor(p)); !errors.Is(err, ErrNotOwnerOnly) {
		t.Errorf("Load = %v, want ErrNotOwnerOnly", err)
	}
	s.Close()
	if _, err := Open(s.Dir()); !errors.Is(err, ErrNotOwnerOnly) {
		t.Errorf("Open = %v, want ErrNotOwnerOnly", err)
	}
}

// A directory made another way inherits its parent's entries and is
// refused, not repaired.
func TestOpenRefusesExistingInheritedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plain")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	icacls(t, dir, "/grant", "*"+sidUsers+":(R)")
	if _, err := Open(dir); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("Open = %v, want ErrNotOwnerOnly", err)
	}
}

// A deny entry takes access away and is accepted. (WD) denies writing
// data only; the runner's user is in Users, and a broader right such
// as (W) would include READ_CONTROL and SYNCHRONIZE and stop the read.
func TestLoadAcceptsDenyEntry(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	icacls(t, s.Path(), "/deny", "*"+sidUsers+":(WD)")
	if _, err := s.Load(resolverFor(p)); err != nil {
		t.Fatalf("Load with a deny entry: %v", err)
	}
}

// The owner-only rule: an owner other than the current user, a missing
// DACL and an allow entry for anyone else are refused. Built from SDDL,
// because changing a file's owner to another user needs a privilege.
func TestCheckSecurity(t *testing.T) {
	user := userSID(t)
	cases := []struct {
		sddl     string
		accepted bool
	}{
		{"O:" + user + "D:P(A;;FA;;;" + user + ")", true},
		{"O:" + user + "D:P(A;OICI;FA;;;" + user + ")(D;;FW;;;" + sidUsers + ")", true},
		{"O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FA;;;" + user + ")", true},
		{"O:" + sidSystem + "D:P(A;;FA;;;" + user + ")", false},
		{"O:BAD:P(A;;FA;;;" + user + ")", false},
		{"O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FR;;;" + sidEveryone + ")", false},
		{"O:" + user + "D:P(A;;FA;;;" + user + ")(A;OICIIO;FR;;;" + sidUsers + ")", false},
		{"O:" + user + "D:P(A;;FA;;;" + user + ")(A;;FA;;;" + sidSystem + ")", false},
		{"O:" + user + "D:NO_ACCESS_CONTROL", false},
		// An object entry (with an object type, so that it stays one).
		{"O:" + user + "D:P(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;" + user + ")", false},
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Fatalf("%s: %v", c.sddl, err)
		}
		err = checkSecurity("x", sd)
		if (err == nil) != c.accepted {
			t.Errorf("%s: err %v, accepted want %v", c.sddl, err, c.accepted)
		}
		if err != nil && !errors.Is(err, ErrNotOwnerOnly) {
			t.Errorf("%s: error %v is not ErrNotOwnerOnly", c.sddl, err)
		}
	}
}

// The directory flush and the open-file rename work on the runner's
// NTFS volume, and the probe leaves no files.
func TestFlushDirAndProbe(t *testing.T) {
	s := openTest(t)
	if err := flushDir(s.Dir()); err != nil {
		t.Errorf("flushing the state directory: %v", err)
	}
	if ok, err := replaceOpenFileSupport(s.Dir()); !ok || err != nil {
		t.Errorf("POSIX-semantics rename over an open file not available on NTFS: %v", err)
	}
	if names := listDir(t, s.Dir()); len(names) != 1 {
		t.Errorf("the probe left files: %v", names)
	}
}

// The probe retries brief sharing violations, reports a definite "not
// supported" as false, and returns any other error.
func TestProbeClassification(t *testing.T) {
	s := openTest(t)
	old := renamePOSIXProbe
	defer func() { renamePOSIXProbe = old }()

	calls := 0
	renamePOSIXProbe = func(a, b string) error {
		calls++
		if calls < 3 {
			return windows.ERROR_SHARING_VIOLATION
		}
		return old(a, b)
	}
	if ok, err := replaceOpenFileSupport(s.Dir()); !ok || err != nil || calls != 3 {
		t.Errorf("transient: ok %v err %v calls %d", ok, err, calls)
	}

	renamePOSIXProbe = func(string, string) error { return windows.ERROR_NOT_SUPPORTED }
	if ok, err := replaceOpenFileSupport(s.Dir()); ok || err != nil {
		t.Errorf("not supported: ok %v err %v", ok, err)
	}

	renamePOSIXProbe = func(string, string) error { return windows.ERROR_ACCESS_DENIED }
	if ok, err := replaceOpenFileSupport(s.Dir()); ok || err == nil {
		t.Errorf("persistent access denied: ok %v err %v", ok, err)
	}

	renamePOSIXProbe = func(string, string) error { return windows.ERROR_DISK_FULL }
	if ok, err := replaceOpenFileSupport(s.Dir()); ok || err == nil {
		t.Errorf("other error: ok %v err %v", ok, err)
	}
	if names := listDir(t, s.Dir()); len(names) != 1 {
		t.Errorf("the probe left files: %v", names)
	}
}

// "Not supported" counts only from the rename itself: the same code from
// the probe's set-up is an error, so CreateReplace stops before wiping.
func TestProbeSetupErrorsAreErrors(t *testing.T) {
	s := openTest(t)
	old := probeCreateTemp
	defer func() { probeCreateTemp = old }()
	for _, code := range []error{windows.ERROR_NOT_SUPPORTED, windows.ERROR_INVALID_PARAMETER, windows.ERROR_DISK_FULL} {
		probeCreateTemp = func(string, string, string) (*os.File, string, error) { return nil, "", code }
		ok, err := replaceOpenFileSupport(s.Dir())
		if ok || err == nil {
			t.Errorf("set-up failing with %v: ok %v err %v, want an error", code, ok, err)
		}
	}
	probeCreateTemp = old
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("a")); err != nil {
		t.Fatal(err)
	}
	probeCreateTemp = func(string, string, string) (*os.File, string, error) {
		return nil, "", windows.ERROR_NOT_SUPPORTED
	}
	if err := s.CreateReplace(p, []byte("b"), nil); err == nil || !strings.Contains(err.Error(), "nothing was replaced") {
		t.Fatalf("CreateReplace with a failing probe set-up = %v", err)
	}
	if !p.hasKey || p.wiped != 0 {
		t.Error("the old key was wiped")
	}
}

// makeReadableByOthers grants Everyone read access to path.
func makeReadableByOthers(t *testing.T, path string) {
	t.Helper()
	icacls(t, path, "/grant", "*"+sidEveryone+":(R)")
}

// A deleted file reached through an inherited handle is refused with
// wording that fits it, and without the owner-only hint's sentinel.
func TestCheckOwnerOnlyHandleDeletedFile(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	f, err := openPrivate(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := s.Save([]byte("y")); err != nil {
		t.Fatal(err)
	}
	err = CheckOwnerOnlyHandle(windows.Handle(f.Fd()), "passphrase file")
	if err == nil || errors.Is(err, ErrNotOwnerOnly) || errors.Is(err, ErrReplaced) || !strings.Contains(err.Error(), "the file was deleted") {
		t.Fatalf("CheckOwnerOnlyHandle of a deleted file = %v", err)
	}
}
