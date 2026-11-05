package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunIDValidation(t *testing.T) {
	s := openTest(t)
	bad := []string{"", ".", "..", "a/b", `a\b`, "a b", "a.b", "../x", "a:b", "é", "a\x00b", strings.Repeat("a", MaxRunIDLen+1)}
	for _, id := range bad {
		if _, err := s.PrepareRun(id); !errors.Is(err, ErrBadRunID) {
			t.Errorf("PrepareRun(%q) = %v, want ErrBadRunID", id, err)
		}
		if err := s.RemoveRun(id); !errors.Is(err, ErrBadRunID) {
			t.Errorf("RemoveRun(%q) = %v, want ErrBadRunID", id, err)
		}
	}
	for _, id := range []string{"a", "A-z_09", strings.Repeat("a", MaxRunIDLen)} {
		d, err := s.PrepareRun(id)
		if err != nil {
			t.Errorf("PrepareRun(%q): %v", id, err)
			continue
		}
		if filepath.Dir(d.Root) != filepath.Join(s.Dir(), RunDirName) {
			t.Errorf("run root %s not directly under run/", d.Root)
		}
	}
}

func TestPrepareRunLayoutAndOwnerOnly(t *testing.T) {
	s := openTest(t)
	d, err := s.PrepareRun("r1")
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(s.Dir(), RunDirName), d.Root, d.Tmp, d.Work, d.Secret} {
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s: %v", dir, err)
		}
		if err := checkDir(dir); err != nil {
			t.Errorf("%s not owner-only: %v", dir, err)
		}
		assertDirOwnerOnly(t, dir)
	}
	if _, err := s.PrepareRun("r1"); err == nil {
		t.Error("PrepareRun of an existing run succeeded")
	}
}

func TestRunSecretFile(t *testing.T) {
	s := openTest(t)
	d, err := s.PrepareRun("r2")
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("s3cret-value")
	path, err := s.WriteRunSecret(d, value)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != d.Secret {
		t.Errorf("secret file %s not in %s", path, d.Secret)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, value) {
		t.Fatalf("read back: %q, %v", got, err)
	}
	assertFileOwnerOnly(t, path)

	if err := s.RemoveRun("r2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("secret file still there: %v", err)
	}
	if _, err := os.Stat(d.Root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("run directory still there: %v", err)
	}
	if err := s.RemoveRun("r2"); err != nil {
		t.Errorf("RemoveRun of a missing run: %v", err)
	}
	if _, err := s.WriteRunSecret(RunDirs{ID: "r2", Secret: filepath.Join(t.TempDir(), "x")}, value); err == nil {
		t.Error("WriteRunSecret accepted a foreign directory")
	}
}

func TestRemoveRunOverwritesSecret(t *testing.T) {
	s := openTest(t)
	d, _ := s.PrepareRun("r3")
	path, err := s.WriteRunSecret(d, []byte("topsecretvalue"))
	if err != nil {
		t.Fatal(err)
	}
	// A hard link keeps the bytes reachable after the name is removed,
	// which shows what was left in the file: zeros.
	link := filepath.Join(s.Dir(), "keep")
	if err := os.Link(path, link); err != nil {
		t.Skipf("hard links not available: %v", err)
	}
	if err := s.RemoveRun("r3"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(link)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("topsecret")) {
		t.Error("secret bytes survived RemoveRun")
	}
}

func TestClearRunsAfterSimulatedCrash(t *testing.T) {
	s := openTest(t)
	// No run/ yet: not an error.
	if err := s.ClearRuns(); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		d, err := s.PrepareRun(id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.WriteRunSecret(d, []byte("v")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d.Work, "out.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A stray file too.
	if err := os.WriteFile(filepath.Join(s.Dir(), RunDirName, "stray"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearRuns(); err != nil {
		t.Fatal(err)
	}
	if names := listDir(t, filepath.Join(s.Dir(), RunDirName)); len(names) != 0 {
		t.Errorf("run/ not empty: %v", names)
	}
	// Still usable.
	if _, err := s.PrepareRun("a"); err != nil {
		t.Errorf("PrepareRun after ClearRuns: %v", err)
	}
}
