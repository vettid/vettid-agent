package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// The token must survive a restart: the second start reads the file the
// first one wrote. On Windows this failed, because the reload judged
// the file by mode bits that Windows always reports as 0666.
func TestLoadOrCreateWSToken_ReloadsItsOwnFile(t *testing.T) {
	dir := t.TempDir()

	first, err := loadOrCreateWSToken(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(first) != 64 {
		t.Errorf("token length = %d, want 64 hex chars", len(first))
	}

	second, err := loadOrCreateWSToken(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if second != first {
		t.Error("second call returned a different token")
	}
}

func TestLoadOrCreateWSToken_RefusesFileOpenToOthers(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateWSToken(dir); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := filepath.Join(dir, "agent.token")

	if runtime.GOOS == "windows" {
		// Everyone (S-1-1-0) gets read access.
		out, err := exec.Command("icacls", path, "/grant", "*S-1-1-0:(R)").CombinedOutput()
		if err != nil {
			t.Fatalf("icacls: %v: %s", err, out)
		}
	} else if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if _, err := loadOrCreateWSToken(dir); err == nil {
		t.Error("loaded a token file that other users can read")
	}
}
