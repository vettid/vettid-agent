//go:build windows

package protect

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writePrivate creates path owned by the current user with a protected
// DACL holding only that user (as internal/state creates its files).
// mode is ignored on Windows.
func writePrivate(t *testing.T, path, content string, _ os.FileMode) {
	t.Helper()
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := tu.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
}

func icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v: %s", args, err, out)
	}
}

// dupHandle returns a duplicate of f's handle, for readFD to own.
func dupHandle(t *testing.T, f *os.File) int {
	t.Helper()
	var h windows.Handle
	me := windows.CurrentProcess()
	if err := windows.DuplicateHandle(me, windows.Handle(f.Fd()), me, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	return int(h)
}

// --passphrase-file and a file handle pass the state file's owner-only
// rule: accepted when owner-only, refused when Everyone or Users can
// read.
func TestPassphraseFileOwnerOnlyDACL(t *testing.T) {
	path := writeFile(t, "Pass-Phrase-1\n", 0o600)
	if got, err := (PassphraseSource{FD: -1, File: path}).Read("", false); err != nil || string(got) != "Pass-Phrase-1" {
		t.Fatalf("owner-only file: %q, %v", got, err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := (PassphraseSource{FD: dupHandle(t, f)}).Read("", false); err != nil || string(got) != "Pass-Phrase-1" {
		t.Fatalf("owner-only file handle: %q, %v", got, err)
	}
	f.Close()

	for _, sid := range []string{"S-1-1-0", "S-1-5-32-545"} {
		path := writeFile(t, "Pass-Phrase-1\n", 0o600)
		icacls(t, path, "/grant", "*"+sid+":(R)")
		_, err := PassphraseSource{FD: -1, File: path}.Read("", false)
		if err == nil || !strings.Contains(err.Error(), sid) || !strings.Contains(err.Error(), "owner only") {
			t.Errorf("file readable by %s: %v", sid, err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		h := dupHandle(t, f)
		_, err = PassphraseSource{FD: h}.Read("", false)
		if err == nil || !strings.Contains(err.Error(), sid) {
			t.Errorf("handle to a file readable by %s: %v", sid, err)
		}
		windows.CloseHandle(windows.Handle(h))
		f.Close()
	}
	// A file made the ordinary way inherits its directory's entries.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte("Pass-Phrase-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (PassphraseSource{FD: -1, File: plain}).Read("", false); err == nil {
		t.Error("a file with inherited entries was accepted")
	}
}

// A pipe handle needs no DACL check.
func TestPassphrasePipeHandle(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w.Write([]byte("Pass-Phrase-1\n"))
	w.Close()
	if got, err := (PassphraseSource{FD: dupHandle(t, r)}).Read("", false); err != nil || string(got) != "Pass-Phrase-1" {
		t.Fatalf("pipe handle: %q, %v", got, err)
	}
}
