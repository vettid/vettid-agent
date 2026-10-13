//go:build !windows

package ownerfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile_Mode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("x")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 0600", perm)
	}
}

func TestCheck_RejectsGroupOrWorldAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("Chmod %o: %v", mode, err)
		}
		if err := Check(path); err == nil {
			t.Errorf("Check accepted mode %o", mode)
		}
	}
}
