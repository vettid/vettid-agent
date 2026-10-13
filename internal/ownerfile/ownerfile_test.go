package ownerfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFile_RoundTripAndCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	want := []byte("hunter2")

	if err := WriteFile(path, want); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("content = %q, want %q", got, want)
	}
	if err := Check(path); err != nil {
		t.Errorf("Check after WriteFile: %v", err)
	}
}

func TestWriteFile_OverwriteTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteFile(path, []byte("a much longer first value")); err != nil {
		t.Fatalf("first WriteFile: %v", err)
	}
	if err := WriteFile(path, []byte("short")); err != nil {
		t.Fatalf("second WriteFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "short" {
		t.Errorf("content = %q, want %q", got, "short")
	}
}

func TestCheck_MissingFile(t *testing.T) {
	err := Check(filepath.Join(t.TempDir(), "absent"))
	if err == nil {
		t.Fatal("Check on a missing file returned nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("Check on a missing file: %v, want a not-exist error", err)
	}
}

func TestMkdirAll_CreatesNestedAndIsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "c")
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	if err := MkdirAll(dir); err != nil {
		t.Errorf("second MkdirAll: %v", err)
	}
	if err := Check(dir); err != nil {
		t.Errorf("Check on created directory: %v", err)
	}
}
