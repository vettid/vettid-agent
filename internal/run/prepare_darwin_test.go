//go:build darwin

package run

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The program runs from its private copy, which Close removes.
func TestStartRunsThePrivateCopy(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	bin := binDir(t)
	p, err := Prepare(exe, bin)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(bin)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("bin folder: %v, %v", fi, err)
	}
	if want := sha256File(t, p.plat.copy); p.SHA256 != want {
		t.Fatalf("copy's hash %s, want %s", want, p.SHA256)
	}
	code, out := runOutput(t, p, helperSpec(t, exe, "exe"))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(out))
	want, _ := filepath.EvalSymlinks(p.plat.copy)
	if got != want {
		t.Fatalf("started %q, want the copy %q", got, want)
	}
	copyPath := p.plat.copy
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatalf("copy left after Close: %v", err)
	}
}

// A bin folder others may use is refused.
func TestPrepareRefusesAnOpenBinFolder(t *testing.T) {
	exe := helperCopy(t, t.TempDir(), "helper")
	bin := binDir(t)
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(exe, bin); err == nil {
		t.Fatal("bin folder 0755 accepted")
	}
}
