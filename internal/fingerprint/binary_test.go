package fingerprint

import (
	"testing"
)

func TestBinaryFingerprint(t *testing.T) {
	fp, err := BinaryFingerprint()
	if err != nil {
		t.Fatalf("BinaryFingerprint: %v", err)
	}

	// Should be a 64-character hex string (SHA-256)
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}

	// Should be deterministic
	fp2, err := BinaryFingerprint()
	if err != nil {
		t.Fatalf("second BinaryFingerprint: %v", err)
	}

	if fp != fp2 {
		t.Error("binary fingerprint should be deterministic")
	}

	t.Logf("Binary fingerprint: %s", fp)
}
