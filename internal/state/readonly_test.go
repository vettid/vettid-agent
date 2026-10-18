package state

import (
	"bytes"
	"errors"
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
