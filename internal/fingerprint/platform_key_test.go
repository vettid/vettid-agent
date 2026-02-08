package fingerprint

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDerivePlatformKey_FromMachine(t *testing.T) {
	key, err := DerivePlatformKey("")
	if err != nil {
		// May fail in minimal environments — that's the expected behavior
		t.Skipf("DerivePlatformKey from machine: %v (may need --platform-key-file)", err)
	}

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Should be deterministic
	key2, err := DerivePlatformKey("")
	if err != nil {
		t.Fatalf("second DerivePlatformKey: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Error("platform key should be deterministic")
	}
}

func TestDerivePlatformKey_FromFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "platform.key")

	// Write a 32-byte key
	keyData := bytes.Repeat([]byte{0x42}, 32)
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := DerivePlatformKey(keyFile)
	if err != nil {
		t.Fatalf("DerivePlatformKey from file: %v", err)
	}

	if !bytes.Equal(key, keyData) {
		t.Error("key from file should match file contents")
	}
}

func TestDerivePlatformKey_FileTooShort(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "short.key")

	if err := os.WriteFile(keyFile, []byte("too short"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	_, err := DerivePlatformKey(keyFile)
	if err == nil {
		t.Error("expected error for key file < 32 bytes")
	}
}

func TestDerivePlatformKey_FileNotFound(t *testing.T) {
	_, err := DerivePlatformKey("/nonexistent/path/to/key")
	if err == nil {
		t.Error("expected error for missing key file")
	}
}

func TestDerivePlatformKey_LargerFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "large.key")

	// Write 64 bytes — should use only first 32
	keyData := bytes.Repeat([]byte{0xAB}, 64)
	if err := os.WriteFile(keyFile, keyData, 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	key, err := DerivePlatformKey(keyFile)
	if err != nil {
		t.Fatalf("DerivePlatformKey: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	if !bytes.Equal(key, keyData[:32]) {
		t.Error("should use first 32 bytes of file")
	}
}

func TestDerivePlatformKeyWithAttrs(t *testing.T) {
	key, attrs, err := DerivePlatformKeyWithAttrs("")
	if err != nil {
		t.Skipf("DerivePlatformKeyWithAttrs: %v (may need --platform-key-file)", err)
	}

	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	if attrs == nil {
		t.Error("attrs should not be nil")
	}

	if attrs.Hostname == "" {
		t.Error("hostname should not be empty")
	}
}

func TestDerivePlatformKeyWithAttrs_FromFile(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "platform.key")
	keyData := bytes.Repeat([]byte{0x42}, 32)
	os.WriteFile(keyFile, keyData, 0600)

	key, attrs, err := DerivePlatformKeyWithAttrs(keyFile)
	if err != nil {
		t.Fatalf("DerivePlatformKeyWithAttrs from file: %v", err)
	}

	if !bytes.Equal(key, keyData) {
		t.Error("key should match file")
	}

	// Attrs should be empty (not applicable for file-based keys)
	if attrs.AttributeCount() != 0 {
		t.Error("attrs should be empty when using file-based key")
	}
}
