//go:build linux || darwin

package run

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A folder owned by a user other than root counts as changeable, whatever
// its mode: its owner can chmod it (AGENT-PLAN §4.9).
func TestWritableOwnedByAnotherUser(t *testing.T) {
	old := ownerOf
	t.Cleanup(func() { ownerOf = old })
	ownerOf = func(os.FileInfo) (uint32, bool) { return 4242, true }
	if w, err := writable("/", true); err != nil || !w {
		t.Fatalf("a folder owned by uid 4242: writable %v, %v", w, err)
	}
	ownerOf = func(os.FileInfo) (uint32, bool) { return 0, false }
	if w, err := writable("/", true); err != nil || !w {
		t.Fatalf("an owner that can't be read: writable %v, %v", w, err)
	}
	ownerOf = old
	if w, err := writable("/", true); err != nil || w {
		t.Fatalf("/ (root's, not group- or world-writable): writable %v, %v", w, err)
	}
}

// A group-writable folder is changeable even when root owns it and this
// user can't write it through its owner bits.
func TestWritableGroupWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anything")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o575); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	old := ownerOf
	t.Cleanup(func() { ownerOf = old })
	ownerOf = func(os.FileInfo) (uint32, bool) { return 0, true }
	if w, err := writable(dir, true); err != nil || !w {
		t.Fatalf("group-writable: writable %v, %v", w, err)
	}
}

// A symbolic link at the program's path is refused by Prepare (it opens
// the path without following a link).
func TestPrepareRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	exe := helperCopy(t, dir, "helper")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	if p, err := Prepare(link, binDir(t)); !errors.Is(err, ErrProgramNotFound) {
		if p != nil {
			p.Close()
		}
		t.Fatalf("Prepare through a link: %v", err)
	}
}

// --run-path checks the directory the link resolves to as well: a link to
// a directory whose name holds the path list separator is refused.
func TestCheckRunPathsChecksTheResolvedPath(t *testing.T) {
	old := writableAt
	t.Cleanup(func() { writableAt = old })
	writableAt = func(string, bool) (bool, error) { return false, nil }
	base := t.TempDir()
	odd := filepath.Join(base, "a:b")
	if err := os.Mkdir(odd, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "plain")
	if err := os.Symlink(odd, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckRunPaths([]string{link}); err == nil || !strings.Contains(err.Error(), "resolves to") {
		t.Fatalf("CheckRunPaths: %v", err)
	}
}

// A secret holding a NUL, or that is not valid UTF-8, is refused before
// anything starts.
func TestStartRefusesABadSecretPOSIX(t *testing.T) {
	for _, v := range [][]byte{{'a', 0, 'b'}, {'a', 0xff, 'b'}} {
		err := checkSecret(&Secret{Name: "MY_SECRET", Value: v})
		if !errors.Is(err, ErrBadRequest) {
			t.Errorf("%q: %v", v, err)
		}
	}
	if err := checkSecret(&Secret{Name: "MY_SECRET", Value: []byte("fine")}); err != nil {
		t.Errorf("a plain value: %v", err)
	}
}
