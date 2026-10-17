//go:build linux || darwin

package protect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/state"
)

func TestReadFileRefusesLooseModes(t *testing.T) {
	for _, m := range []os.FileMode{0o640, 0o604, 0o660, 0o644} {
		_, err := PassphraseSource{FD: -1, File: writeFile(t, "Pass-Phrase-1\n", m)}.Read("", false)
		if err == nil || !strings.Contains(err.Error(), "owner only") {
			t.Errorf("mode %04o: %v", m, err)
		}
	}
	if _, err := (PassphraseSource{FD: -1, File: writeFile(t, "Pass-Phrase-1\n", 0o400)}).Read("", false); err != nil {
		t.Errorf("mode 0400: %v", err)
	}
}

func TestReadFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// readFD takes ownership of the descriptor it is given and closes
	// it, so give it a duplicate.
	fd, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Pass-Phrase-1\nnot read\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	got, err := PassphraseSource{FD: fd}.Read("", false)
	if err != nil || string(got) != "Pass-Phrase-1" {
		t.Fatalf("Read = %q, %v", got, err)
	}
	if err := syscall.Close(fd); err == nil {
		t.Error("readFD left the descriptor open")
	}
}

// dupOf returns a duplicate descriptor of f, for readFD to own.
func dupOf(t *testing.T, f *os.File) int {
	t.Helper()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func TestReadFDRefusesStandardDescriptors(t *testing.T) {
	for _, fd := range []int{0, 1, 2} {
		_, err := PassphraseSource{FD: fd}.Read("", false)
		if err == nil || !strings.Contains(err.Error(), "standard input, output and error") {
			t.Errorf("fd %d: %v", fd, err)
		}
		// Still open: not closed by the refusal.
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			t.Errorf("fd %d was closed: %v", fd, err)
		}
	}
}

func TestReadFDRefusesOtherKinds(t *testing.T) {
	d, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	fd := dupOf(t, d)
	defer syscall.Close(fd)
	if _, err := (PassphraseSource{FD: fd}).Read("", false); err == nil || !strings.Contains(err.Error(), "not a pipe or a regular file") {
		t.Errorf("directory descriptor: %v", err)
	}
	if _, err := (PassphraseSource{FD: 1 << 20}).Read("", false); err == nil {
		t.Error("a descriptor that is not open was accepted")
	}
}

func TestReadFDRegularFile(t *testing.T) {
	f, err := os.Open(writeFile(t, "Pass-Phrase-1\n", 0o600))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got, err := (PassphraseSource{FD: dupOf(t, f)}).Read("", false); err != nil || string(got) != "Pass-Phrase-1" {
		t.Fatalf("Read = %q, %v", got, err)
	}
}

// With a state directory open, no descriptor is read: a descriptor
// number can never name the store's own lock file. The lock stays held.
func TestReadFDRefusedWhileStoreOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	lock, err := os.Open(filepath.Join(dir, state.LockFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	fd := dupOf(t, lock)
	defer syscall.Close(fd)
	_, err = PassphraseSource{FD: fd}.Read("", false)
	if err == nil || !strings.Contains(err.Error(), "before the state directory is opened") {
		t.Fatalf("Read with a store open = %v", err)
	}
	if _, err := state.Open(dir); !errors.Is(err, state.ErrInUse) {
		t.Fatalf("second Open = %v, want ErrInUse (the first lock must still be held)", err)
	}
	s.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w.Write([]byte("Pass-Phrase-1\n"))
	w.Close()
	if _, err := (PassphraseSource{FD: dupOf(t, r)}).Read("", false); err != nil {
		t.Fatalf("Read after Close: %v", err)
	}
}

// A FIFO given as --passphrase-file is refused at once, not waited on.
func TestReadFileRefusesFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := PassphraseSource{FD: -1, File: path}.Read("", false)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("Read of a FIFO = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Read of a FIFO hung")
	}
}

// A regular file through --passphrase-fd gets the owner-only check; a
// pipe does not need one.
func TestReadFDRegularFileMustBeOwnerOnly(t *testing.T) {
	f, err := os.Open(writeFile(t, "Pass-Phrase-1\n", 0o644))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := dupOf(t, f)
	defer syscall.Close(fd)
	if _, err := (PassphraseSource{FD: fd}).Read("", false); err == nil || !strings.Contains(err.Error(), "owner only") {
		t.Fatalf("Read of a 0644 file through a descriptor = %v", err)
	}
}

// writePrivate writes content to path with exactly mode.
func writePrivate(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// A named FIFO on disk passes only if no one else can write to it.
func TestReadFDRefusesWritableFIFO(t *testing.T) {
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o600, true}, {0o620, false}, {0o602, false}, {0o640, true}} {
		path := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		w, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("Pass-Phrase-1\n"))
		w.Close()
		fd := dupOf(t, r)
		_, err = PassphraseSource{FD: fd}.Read("", false)
		r.Close()
		if c.ok && err != nil {
			t.Errorf("FIFO mode %04o: %v", c.mode, err)
		}
		if !c.ok {
			syscall.Close(fd)
			if err == nil || !strings.Contains(err.Error(), "writable by other users") {
				t.Errorf("FIFO mode %04o: %v, want a refusal", c.mode, err)
			}
		}
	}
}
