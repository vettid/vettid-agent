package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The lock helper: the test binary re-executed with this variable set
// tries to open the state directory it names and exits 0 if it got the
// lock, 3 on ErrInUse and 4 on any other error.
const lockHelperEnv = "VETTID_AGENT_STATE_LOCK_HELPER"

func TestMain(m *testing.M) {
	if dir := os.Getenv(lockHelperEnv); dir != "" {
		s, err := Open(dir)
		switch {
		case err == nil:
			s.Close()
			os.Exit(0)
		case errors.Is(err, ErrInUse):
			fmt.Fprintln(os.Stderr, err)
			os.Exit(3)
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(4)
		}
	}
	os.Exit(m.Run())
}

func TestCreateLoadSave(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if ok, err := s.Exists(); err != nil || ok {
		t.Fatalf("Exists before Create = %v, %v", ok, err)
	}
	if err := s.Create(p, []byte("one")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ok, _ := s.Exists(); !ok {
		t.Fatal("Exists after Create = false")
	}
	h1 := readHeader(t, s.Path())

	if err := s.Save([]byte("two")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	h2 := readHeader(t, s.Path())
	if !bytes.Equal(h1.WrappedKey, h2.WrappedKey) || h1.CreatedAt != h2.CreatedAt || h1.Protector != h2.Protector {
		t.Error("Save changed the protector, wrapped key or created_at")
	}
	if bytes.Equal(h1.Nonce, h2.Nonce) {
		t.Error("Save reused the nonce")
	}
	s.Close()

	s2, err := Open(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Load(resolverFor(p))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(got) != "two" {
		t.Errorf("Load = %q, want %q", got, "two")
	}
	if s2.Protector() != p {
		t.Error("Protector() is not the loaded protector")
	}
	// Save after Load keeps the data key.
	if err := s2.Save([]byte("three")); err != nil {
		t.Fatal(err)
	}
	if h3 := readHeader(t, s2.Path()); !bytes.Equal(h3.WrappedKey, h1.WrappedKey) {
		t.Error("Save after Load changed the wrapped key")
	}
	if got, _ := s2.Load(resolverFor(p)); string(got) != "three" {
		t.Errorf("Load = %q", got)
	}
}

// Create makes a new data key every time (a new pairing).
func TestCreateMakesNewDataKey(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("a")); err != nil {
		t.Fatal(err)
	}
	k1 := append([]byte{}, s.dataKey...)
	w1 := readHeader(t, s.Path()).WrappedKey
	if err := s.Create(p, []byte("b")); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, s.dataKey) {
		t.Error("Create reused the data key")
	}
	// The test protector wraps deterministically, so a different wrapped
	// key on disk means a different data key.
	if bytes.Equal(w1, readHeader(t, s.Path()).WrappedKey) {
		t.Error("the wrapped key on disk did not change")
	}
}

func TestSaveBeforeCreateOrLoad(t *testing.T) {
	s := openTest(t)
	if err := s.Save([]byte("x")); !errors.Is(err, ErrNotLoaded) {
		t.Fatalf("Save = %v, want ErrNotLoaded", err)
	}
}

func TestLoadMissing(t *testing.T) {
	s := openTest(t)
	if _, err := s.Load(resolverFor()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load = %v, want ErrNotFound", err)
	}
}

func TestLoadWrongProtector(t *testing.T) {
	s := openTest(t)
	if err := s.Create(newFixedProtector(seq(0x40, 32)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(resolverFor(newFixedProtector(seq(0x41, 32)))); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("Load with another key = %v, want ErrUnwrap", err)
	}
	if _, err := s.Load(resolverFor()); !errors.Is(err, ErrUnknownProtector) {
		t.Fatalf("Load with no protector = %v, want ErrUnknownProtector", err)
	}
	if _, err := s.Load(nil); !errors.Is(err, ErrUnknownProtector) {
		t.Fatalf("Load with nil resolver = %v, want ErrUnknownProtector", err)
	}
}

// A crash between writing the temporary file and renaming it leaves the
// old state readable.
func TestCrashBeforeRenameKeepsOldState(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("old")); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("simulated crash")
	var tmpSeen string
	testHookBeforeRename = func(tmp string) error {
		tmpSeen = tmp
		return crash
	}
	err := s.Save([]byte("new"))
	testHookBeforeRename = nil
	if !errors.Is(err, crash) {
		t.Fatalf("Save = %v, want the simulated crash", err)
	}
	// As after a real crash, the complete temporary file is still there.
	if _, err := os.Stat(tmpSeen); err != nil {
		t.Fatalf("temporary file: %v", err)
	}
	dir := s.Dir()
	s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Load(resolverFor(p))
	if err != nil {
		t.Fatalf("Load after crash: %v", err)
	}
	if string(got) != "old" {
		t.Errorf("Load after crash = %q, want %q", got, "old")
	}
	// Open removed the leftover temporary file.
	if names := listDir(t, dir); len(names) != 2 {
		t.Errorf("state directory holds %v, want the state and lock files only", names)
	}
}

// A failed write (not a crash) removes its temporary file.
func TestFailedWriteLeavesNoTemp(t *testing.T) {
	s := openTest(t)
	if err := s.Create(newFixedProtector(seq(0x40, 32)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	// A directory at the state file's path makes the rename fail.
	if err := os.Remove(s.Path()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("y")); err == nil {
		t.Fatal("Save over a directory succeeded")
	}
	for _, n := range listDir(t, s.Dir()) {
		if strings.HasSuffix(n, tempSuffix) {
			t.Errorf("temporary file %s left behind", n)
		}
	}
}

func TestLockSecondHandle(t *testing.T) {
	s := openTest(t)
	if _, err := Open(s.Dir()); !errors.Is(err, ErrInUse) {
		t.Fatalf("second Open = %v, want ErrInUse", err)
	}
	if !strings.Contains(ErrInUse.Error(), "in use by another agent app") {
		t.Errorf("ErrInUse text %q", ErrInUse)
	}
	s.Close()
	s2, err := Open(s.Dir())
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	s2.Close()
}

func TestLockSecondProcess(t *testing.T) {
	s := openTest(t)
	run := func() int {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), lockHelperEnv+"="+s.Dir())
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		switch {
		case err == nil:
			return 0
		case errors.As(err, &ee):
			if ee.ExitCode() == 3 && !strings.Contains(string(out), "in use by another agent app") {
				t.Errorf("helper output %q", out)
			}
			if ee.ExitCode() == 4 {
				t.Logf("helper output %q", out)
			}
			return ee.ExitCode()
		default:
			t.Fatalf("helper: %v", err)
			return -1
		}
	}
	if code := run(); code != 3 {
		t.Fatalf("second process exit %d, want 3 (in use)", code)
	}
	s.Close()
	if code := run(); code != 0 {
		t.Fatalf("second process after Close exit %d, want 0", code)
	}
}

func TestClosed(t *testing.T) {
	s := openTest(t)
	s.Close()
	if err := s.Create(newFixedProtector(seq(0x40, 32)), nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Create after Close = %v", err)
	}
	if _, err := s.Load(nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Load after Close = %v", err)
	}
	if err := s.Wipe(nil); !errors.Is(err, ErrClosed) {
		t.Errorf("Wipe after Close = %v", err)
	}
}

func TestWipe(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("secret state")); err != nil {
		t.Fatal(err)
	}
	size := fileSize(t, s.Path())
	// A second name for the same file shows whether the bytes were
	// overwritten in place before the delete.
	link := filepath.Join(t.TempDir(), "link")
	linked := os.Link(s.Path(), link) == nil
	// A leftover temporary file from an interrupted write.
	tmp := filepath.Join(s.Dir(), tempPrefix+"00"+tempSuffix)
	if err := os.WriteFile(tmp, []byte("older state"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := s.Wipe(nil); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if p.wiped != 1 {
		t.Errorf("protector Wipe called %d times, want 1", p.wiped)
	}
	if _, err := os.Lstat(s.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state file still there: %v", err)
	}
	if _, err := os.Lstat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("temporary file still there: %v", err)
	}
	if s.dataKey != nil || s.Protector() != nil {
		t.Error("keys kept after Wipe")
	}
	if linked {
		got, err := os.ReadFile(link)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(got)) != size || !bytes.Equal(got, make([]byte, size)) {
			t.Error("the state file's bytes were not overwritten with zeros before the delete")
		}
	} else {
		t.Log("no hard links here; overwrite not observed")
	}
	if _, err := s.Load(resolverFor(p)); !errors.Is(err, ErrNotFound) {
		t.Errorf("Load after Wipe = %v, want ErrNotFound", err)
	}
	if err := s.Save([]byte("x")); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("Save after Wipe = %v, want ErrNotLoaded", err)
	}
}

// forget without the passphrase: the file is not opened, the protector
// comes from the header's name.
func TestWipeWithoutLoad(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	if err := s.Create(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	dir := s.Dir()
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	other := newFixedProtector(seq(0x41, 32)) // the same name, another key
	if err := s2.Wipe(resolverFor(other)); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	if other.wiped != 1 {
		t.Errorf("resolved protector Wipe called %d times, want 1", other.wiped)
	}
	if ok, _ := s2.Exists(); ok {
		t.Error("state file still there")
	}
}

func TestWipeNothing(t *testing.T) {
	s := openTest(t)
	if err := s.Wipe(resolverFor()); err != nil {
		t.Fatalf("Wipe with no state: %v", err)
	}
}

type failingProtector struct{ *fixedProtector }

func (failingProtector) Wipe() error { return errors.New("key not deleted") }

// A protector that cannot delete its key does not stop the file's
// deletion, and the error says so.
func TestWipeProtectorFailure(t *testing.T) {
	s := openTest(t)
	p := failingProtector{newFixedProtector(seq(0x40, 32))}
	if err := s.Create(p, []byte("x")); err != nil {
		t.Fatal(err)
	}
	err := s.Wipe(nil)
	if err == nil || !strings.Contains(err.Error(), "key not deleted") {
		t.Fatalf("Wipe = %v, want the protector's error", err)
	}
	if ok, _ := s.Exists(); ok {
		t.Error("state file kept after the protector failed")
	}
}

func TestStateTooLarge(t *testing.T) {
	s := openTest(t)
	if err := s.Create(newFixedProtector(seq(0x40, 32)), make([]byte, MaxStateLen+1)); err == nil {
		t.Fatal("Create accepted a state over MaxStateLen")
	}
	if ok, _ := s.Exists(); ok {
		t.Error("a file was written")
	}
}

func TestInvalidProtectorName(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(seq(0x40, 32))
	p.name = "Bad Name"
	if err := s.Create(p, nil); err == nil {
		t.Fatal("Create accepted an invalid protector name")
	}
}

func TestLoadRefusesSymlink(t *testing.T) {
	s := openTest(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, s.Path()); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	if _, err := s.Load(resolverFor()); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("Load through a symbolic link = %v, want ErrNotOwnerOnly", err)
	}
	// Wipe deletes the link and leaves its target alone.
	if err := s.Wipe(nil); err == nil {
		t.Log("Wipe returned nil")
	}
	if got, _ := os.ReadFile(target); string(got) != "x" {
		t.Error("Wipe wrote through the link")
	}
}

func TestLoadRefusesHardLink(t *testing.T) {
	s := openTest(t)
	if err := s.Create(newFixedProtector(seq(0x40, 32)), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(s.Path(), filepath.Join(s.Dir(), "second-name")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	if _, err := s.Load(resolverFor(newFixedProtector(seq(0x40, 32)))); !errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("Load of a file with two links = %v, want ErrNotOwnerOnly", err)
	}
}

func readHeader(t *testing.T, path string) *header {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hb, _, err := splitFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	h, err := parseHeader(hb)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}
