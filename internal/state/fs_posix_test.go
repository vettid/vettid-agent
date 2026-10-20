//go:build linux || darwin

package state

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The directory is 0700 and the files 0600 whatever the umask.
func TestOwnerOnlyModesWhateverTheUmask(t *testing.T) {
	for _, umask := range []int{0o000, 0o022, 0o277} {
		t.Run("", func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "a", "state")
			old := syscall.Umask(umask)
			defer syscall.Umask(old)
			s, err := Open(dir)
			if err != nil {
				t.Fatalf("Open with umask %04o: %v", umask, err)
			}
			defer s.Close()
			if err := s.Create(newFixedProtector(seq(0x40, 32)), []byte("x")); err != nil {
				t.Fatalf("Create with umask %04o: %v", umask, err)
			}
			if err := s.Save([]byte("y")); err != nil {
				t.Fatalf("Save with umask %04o: %v", umask, err)
			}
			if _, err := s.Load(resolverFor(newFixedProtector(seq(0x40, 32)))); err != nil {
				t.Fatalf("Load with umask %04o: %v", umask, err)
			}
			if m := mode(t, dir); m != 0o700 {
				t.Errorf("umask %04o: directory mode %04o, want 0700", umask, m)
			}
			if m := mode(t, filepath.Dir(dir)); m&0o077 != 0 {
				t.Errorf("umask %04o: parent created with mode %04o", umask, m)
			}
			if m := mode(t, s.Path()); m != 0o600 {
				t.Errorf("umask %04o: state file mode %04o, want 0600", umask, m)
			}
			if m := mode(t, filepath.Join(dir, LockFileName)); m != 0o600 {
				t.Errorf("umask %04o: lock file mode %04o, want 0600", umask, m)
			}
		})
	}
}

func TestLoadRefusesGroupOrWorldAccessibleFile(t *testing.T) {
	for _, m := range []os.FileMode{0o640, 0o620, 0o604, 0o602, 0o610} {
		s := openTest(t)
		p := newFixedProtector(seq(0x40, 32))
		if err := s.Create(p, []byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(s.Path(), m); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(resolverFor(p)); !errors.Is(err, ErrNotOwnerOnly) {
			t.Errorf("Load of a %04o file = %v, want ErrNotOwnerOnly", m, err)
		}
	}
}

func TestRefusesGroupOrWorldAccessibleDirectory(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Dir(), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(resolverFor(p)); !errors.Is(err, ErrNotOwnerOnly) {
		t.Errorf("Load in a 0750 directory = %v, want ErrNotOwnerOnly", err)
	}
	s.Close()
	if _, err := Open(s.Dir()); !errors.Is(err, ErrNotOwnerOnly) {
		t.Errorf("Open of a 0750 directory = %v, want ErrNotOwnerOnly", err)
	}
	if err := os.Chmod(s.Dir(), 0o701); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(s.Dir()); !errors.Is(err, ErrNotOwnerOnly) {
		t.Errorf("Open of a 0701 directory = %v, want ErrNotOwnerOnly", err)
	}
}

// An existing directory is checked, not repaired.
func TestOpenRefusesExistingLooseDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("Open = %v, want ErrNotOwnerOnly", err)
	}
	if m := mode(t, dir); m != 0o755 {
		t.Errorf("Open changed the directory's mode to %04o", m)
	}
}

func TestOpenRefusesSymlinkDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("Open of a symbolic link = %v, want ErrNotOwnerOnly", err)
	}
}

// A file or directory owned by another user is refused. Changing a
// file's owner needs root, so the rule is tested directly.
func TestCheckOwnerMode(t *testing.T) {
	cases := []struct {
		mode     os.FileMode
		uid      uint32
		euid     uint32
		accepted bool
	}{
		{0o600, 1000, 1000, true},
		{0o700, 1000, 1000, true},
		{0o400, 1000, 1000, true},
		{0o600, 0, 1000, false},
		{0o600, 1001, 1000, false},
		{0o640, 1000, 1000, false},
		{0o604, 1000, 1000, false},
		{0o710, 1000, 1000, false},
	}
	for _, c := range cases {
		err := checkOwnerMode("x", c.mode, c.uid, c.euid)
		if (err == nil) != c.accepted {
			t.Errorf("mode %04o uid %d euid %d: err %v, accepted want %v", c.mode, c.uid, c.euid, err, c.accepted)
		}
		if err != nil && !errors.Is(err, ErrNotOwnerOnly) {
			t.Errorf("error %v is not ErrNotOwnerOnly", err)
		}
	}
}

func TestLoadRefusesFIFO(t *testing.T) {
	s := openTest(t)
	if err := syscall.Mkfifo(s.Path(), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, err := s.Load(resolverFor()); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("Load of a FIFO = %v, want ErrNotOwnerOnly", err)
	}
}

// makeReadableByOthers gives group and others read access to path.
func makeReadableByOthers(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}
