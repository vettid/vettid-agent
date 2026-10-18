package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
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
// (each save a rename over the file) always see one whole state, never
// a torn or missing one.
func TestReadOnlyDuringWrites(t *testing.T) {
	s := openTest(t)
	p := newFixedProtector(bytes.Repeat([]byte{7}, 32))
	if err := s.Create(p, []byte(`{"n":0}`)); err != nil {
		t.Fatal(err)
	}
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
	reads := 0
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("save: %v", err)
			}
			if reads == 0 {
				t.Fatal("no read happened during the writes")
			}
			return
		default:
		}
		v, err := ReadOnly(s.Dir(), func(string) Protector { return p })
		if err != nil {
			t.Fatalf("read %d during writes: %v", reads, err)
		}
		if !bytes.HasPrefix(v.State, []byte(`{"n":`)) {
			t.Fatalf("read %d: %q", reads, v.State)
		}
		reads++
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
