package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestReadOnly: the state is read while another Store holds the lock,
// which it keeps; nothing in the directory changes (a leftover
// temporary file stays); a missing directory or file is ErrNotFound; a
// wrong key is refused as Load refuses it.
func TestReadOnly(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(s.Dir(), tempPrefix+"0123456789abcdef0123456789abcdef"+tempSuffix)
	if err := os.WriteFile(tmp, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := listDir(t, s.Dir())
	v, err := ReadOnly(s.Dir(), func(string) Protector { return p })
	if err != nil {
		t.Fatal(err)
	}
	if string(v.State) != `{"x":1}` || v.Protector != testProtectorName || !v.CreatedAt.Equal(s.CreatedAt()) {
		t.Errorf("view %+v", v)
	}
	if after := listDir(t, s.Dir()); len(after) != len(before) {
		t.Errorf("directory changed: %v -> %v", before, after)
	}
	if _, err := Open(s.Dir()); !errors.Is(err, ErrInUse) {
		t.Errorf("the lock was lost: %v", err)
	}
	if err := s.Save([]byte(`{"x":2}`)); err != nil {
		t.Fatalf("the holder cannot save after a read: %v", err)
	}
	other := newFixedProtector(bytes.Repeat([]byte{8}, 32))
	if _, err := ReadOnly(s.Dir(), func(string) Protector { return other }); !errors.Is(err, ErrUnwrap) {
		t.Errorf("wrong key: %v", err)
	}
	if _, err := ReadOnly(filepath.Join(t.TempDir(), "absent"), nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("absent directory: %v", err)
	}
	empty := openTest(t)
	if _, err := ReadOnly(empty.Dir(), nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("no state file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(t.TempDir(), "absent")); !os.IsNotExist(err) {
		t.Error("ReadOnly created a directory")
	}
}

// TestReadOnlyDuringWrites: reads while the lock holder keeps saving
// (each save a rename over the file) see one whole state, never a torn
// or missing one, and are never refused as not private. A read whose
// every attempt loses the race to a save fails with ErrReplaced, which
// is safe (nothing was read); where every open is slow (an antivirus
// filter scanning each new file) that can happen while the writer
// runs, so it is allowed then, and a read after the writes must work.
func TestReadOnlyDuringWrites(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	resolve := func(string) Protector { return p }
	done := make(chan error, 1)
	go func() {
		for i := 1; i <= 200; i++ {
			if err := s.Save([]byte(fmt.Sprintf(`{"n":%d}`, i))); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	reads, ok, lost := 0, 0, 0
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("save: %v", err)
			}
			if reads == 0 {
				t.Fatal("no read happened during the writes")
			}
			v, err := ReadOnly(s.Dir(), resolve)
			if err != nil || string(v.State) != `{"n":200}` {
				t.Fatalf("read after the writes: %v", err)
			}
			t.Logf("%d reads during the writes: %d whole, %d lost every attempt to a save", reads, ok, lost)
			// Without an antivirus filter slowing every open, some reads
			// during the writes must win.
			if ok == 0 && runtime.GOOS != "windows" {
				t.Fatal("no read during the writes succeeded")
			}
			return
		default:
		}
		v, err := ReadOnly(s.Dir(), resolve)
		reads++
		switch {
		case err == nil:
			if !bytes.HasPrefix(v.State, []byte(`{"n":`)) {
				t.Fatalf("read %d: %q", reads, v.State)
			}
			ok++
		case errors.Is(err, ErrReplaced) && !errors.Is(err, ErrNotOwnerOnly):
			lost++
		default:
			t.Fatalf("read %d during writes: %v", reads, err)
		}
	}
}

// replaceAfterOpen makes the next n opens by readNoFollow find their
// file replaced by a save (a rename over the path) before the check, as
// a reader that loses the race to the lock holder does.
func replaceAfterOpen(t *testing.T, s *Store, n int) *int {
	t.Helper()
	saves := new(int)
	testHookAfterOpen = func(string) {
		if *saves >= n {
			return
		}
		*saves++
		if err := s.Save([]byte(fmt.Sprintf(`{"n":%d}`, *saves))); err != nil {
			t.Errorf("save %d: %v", *saves, err)
		}
	}
	t.Cleanup(func() { testHookAfterOpen = nil })
	return saves
}

func countSleeps(t *testing.T) *[]time.Duration {
	t.Helper()
	var d []time.Duration
	readOnlySleep = func(x time.Duration) { d = append(d, x) }
	t.Cleanup(func() { readOnlySleep = time.Sleep })
	return &d
}

// An open file that a rename then replaces has 0 links. checkFile
// reports that as ErrReplaced with the count, not as a privacy refusal.
func TestCheckFileReplacedWhileOpen(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	f, err := openPrivate(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := checkFile(f); err != nil {
		t.Fatalf("before the save: %v", err)
	}
	if err := s.Save([]byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	err = checkFile(f)
	if !errors.Is(err, ErrReplaced) || errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("checkFile of the replaced file = %v, want ErrReplaced", err)
	}
	if !strings.Contains(err.Error(), "0 links") {
		t.Errorf("error %q does not give the link count", err)
	}
}

// A replaced file that is also not private (here, readable by others)
// is refused as not private, not classed as replaced: Load and ReadOnly
// return ErrNotOwnerOnly, and ReadOnly does not retry.
func TestReplacedFileNotPrivateIsRefused(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	f, err := openPrivate(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	makeReadableByOthers(t, s.Path())
	if err := s.Save([]byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	err = checkFile(f)
	if !errors.Is(err, ErrNotOwnerOnly) || errors.Is(err, ErrReplaced) {
		t.Fatalf("checkFile of a replaced, readable-by-others file = %v, want ErrNotOwnerOnly", err)
	}

	sleeps := countSleeps(t)
	testHookAfterOpen = func(path string) {
		testHookAfterOpen = nil
		makeReadableByOthers(t, path)
		if err := s.Save([]byte(`{"n":2}`)); err != nil {
			t.Errorf("save: %v", err)
		}
	}
	t.Cleanup(func() { testHookAfterOpen = nil })
	_, err = ReadOnly(s.Dir(), func(string) Protector { return p })
	if !errors.Is(err, ErrNotOwnerOnly) || errors.Is(err, ErrReplaced) {
		t.Fatalf("ReadOnly = %v, want ErrNotOwnerOnly", err)
	}
	if len(*sleeps) != 0 {
		t.Errorf("ReadOnly retried a file that is not private %d times", len(*sleeps))
	}
}

// ReadOnly drops a replaced file's bytes and reads the path again, with
// growing pauses, and returns the file that was there at the last read.
func TestReadOnlyRetriesReplacedFile(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	sleeps := countSleeps(t)
	saves := replaceAfterOpen(t, s, 3)
	v, err := ReadOnly(s.Dir(), func(string) Protector { return p })
	if err != nil {
		t.Fatalf("ReadOnly = %v", err)
	}
	if *saves != 3 || string(v.State) != `{"n":3}` {
		t.Errorf("%d saves, read %q, want 3 and the last state", *saves, v.State)
	}
	want := []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	if fmt.Sprint(*sleeps) != fmt.Sprint(want) {
		t.Errorf("pauses %v, want %v", *sleeps, want)
	}
}

// A file replaced on every attempt: ReadOnly stops after
// readOnlyAttempts with ErrReplaced, having read nothing.
func TestReadOnlyGivesUpOnEndlessReplacement(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	sleeps := countSleeps(t)
	saves := replaceAfterOpen(t, s, 1<<30)
	v, err := ReadOnly(s.Dir(), func(string) Protector { return p })
	if v != nil || !errors.Is(err, ErrReplaced) || errors.Is(err, ErrNotOwnerOnly) {
		t.Fatalf("ReadOnly = %v, %v; want ErrReplaced", v, err)
	}
	if *saves != readOnlyAttempts || len(*sleeps) != readOnlyAttempts-1 {
		t.Errorf("%d attempts, %d pauses; want %d attempts", *saves, len(*sleeps), readOnlyAttempts)
	}
	var total time.Duration
	for _, d := range *sleeps {
		total += d
		if d > 100*time.Millisecond {
			t.Errorf("pause %v longer than 100 ms", d)
		}
	}
	if total < time.Second || total > 2*time.Second {
		t.Errorf("pauses add up to %v, want 1 to 2 s", total)
	}
}

// A state file with a second hard link is refused by Load and by
// ReadOnly, at once (no retry), with the link count in the error.
func TestRefusesHardLinkedStateFile(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(s.Path(), filepath.Join(s.Dir(), "second-name")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	check := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrNotOwnerOnly) || errors.Is(err, ErrReplaced) {
			t.Fatalf("%s = %v, want ErrNotOwnerOnly", what, err)
		}
		if !strings.Contains(err.Error(), "has 2 links") {
			t.Errorf("%s: error %q does not give the link count", what, err)
		}
	}
	_, err := s.Load(func(string) Protector { return p })
	check("Load", err)
	sleeps := countSleeps(t)
	_, err = ReadOnly(s.Dir(), func(string) Protector { return p })
	check("ReadOnly", err)
	if len(*sleeps) != 0 {
		t.Errorf("ReadOnly retried a hard-linked file %d times", len(*sleeps))
	}
}

func TestCheckLinks(t *testing.T) {
	if err := checkLinks("x", 1); err != nil {
		t.Errorf("1 link: %v", err)
	}
	if err := checkLinks("x", 0); !errors.Is(err, ErrReplaced) || errors.Is(err, ErrNotOwnerOnly) {
		t.Errorf("0 links: %v", err)
	}
	for _, n := range []uint64{2, 3, 1 << 32} {
		err := checkLinks("x", n)
		if !errors.Is(err, ErrNotOwnerOnly) || errors.Is(err, ErrReplaced) || !strings.Contains(err.Error(), fmt.Sprintf("has %d links", n)) {
			t.Errorf("%d links: %v", n, err)
		}
	}
}

// TestCreateReplaceSentinels: a CreateReplace failure says what it left:
// nothing changed (a failing probe, a failing old-key wipe: neither
// sentinel, the old state still loads), or the old state may be gone
// with the new one not in place (a write failing after the wipe:
// ErrReplaceIncomplete).
func TestCreateReplaceSentinels(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	setup := func(t *testing.T) (*Store, *fixedProtector) {
		s := openTest(t)
		p := newFixedProtector(key)
		if err := s.Create(p, []byte(`{"old":1}`)); err != nil {
			t.Fatal(err)
		}
		return s, p
	}
	stillOld := func(t *testing.T, s *Store, p *fixedProtector) {
		t.Helper()
		pt, err := s.Load(func(string) Protector { return p })
		if err != nil || string(pt) != `{"old":1}` {
			t.Errorf("old state: %q %v", pt, err)
		}
	}
	noSentinel := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || errors.Is(err, ErrReplaceIncomplete) || errors.Is(err, ErrReplacedPartly) || errors.Is(err, ErrNotDurable) {
			t.Errorf("got %v, want an error with no sentinel", err)
		}
	}

	t.Run("probe", func(t *testing.T) {
		s, p := setup(t)
		old := probeReplaceOpen
		probeReplaceOpen = func(string) (bool, error) { return false, errors.New("sharing violation") }
		defer func() { probeReplaceOpen = old }()
		noSentinel(t, s.CreateReplace(newFixedProtector(key), []byte(`{"new":1}`), nil))
		stillOld(t, s, p)
	})
	t.Run("wipe", func(t *testing.T) {
		s, p := setup(t)
		p.failWipes = 1
		noSentinel(t, s.CreateReplace(p, []byte(`{"new":1}`), nil))
		stillOld(t, s, p)
	})
	t.Run("write after the wipe", func(t *testing.T) {
		s, p := setup(t)
		testHookBeforeRename = func(string) error { return errors.New("disk full") }
		defer func() { testHookBeforeRename = nil }()
		err := s.CreateReplace(p, []byte(`{"new":1}`), nil)
		if !errors.Is(err, ErrReplaceIncomplete) || errors.Is(err, ErrReplacedPartly) {
			t.Errorf("got %v", err)
		}
	})
}
