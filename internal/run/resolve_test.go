package run

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// makeExec creates an executable file named name in dir (with .exe on
// Windows) and returns its path.
func makeExec(t *testing.T, dir, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("not really a program"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func evalAbs(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolveBareNameFixedPathOnly(t *testing.T) {
	decoyDir := t.TempDir()
	makeExec(t, decoyDir, "vettiddecoyprog")
	// The inherited PATH names the decoy directory; it must not be used.
	t.Setenv("PATH", decoyDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := Resolve("vettiddecoyprog", nil); !errors.Is(err, ErrProgramNotFound) {
		t.Fatalf("decoy on PATH: err = %v, want program_not_found", err)
	}
	// The operator's --run-path adds it.
	got, err := Resolve("vettiddecoyprog", []string{decoyDir})
	if err != nil {
		t.Fatal(err)
	}
	if got != evalAbs(t, makeExec(t, decoyDir, "vettiddecoyprog")) {
		t.Errorf("resolved to %s", got)
	}
	// A program that is on the fixed path is found without help.
	sys := "sh"
	if runtime.GOOS == "windows" {
		sys = "cmd"
	}
	p, err := Resolve(sys, nil)
	if err != nil {
		t.Fatalf("%s: %v", sys, err)
	}
	var inFixed bool
	for _, d := range FixedPath() {
		if rd, err := filepath.EvalSymlinks(d); err == nil && strings.EqualFold(filepath.Dir(p), rd) {
			inFixed = true
		}
	}
	if !inFixed && runtime.GOOS == "windows" {
		t.Errorf("%s resolved to %s, outside the fixed path", sys, p)
	}
}

func TestResolveFixedBeforeRunPath(t *testing.T) {
	// A run-path directory cannot shadow a fixed-path program.
	shadow := t.TempDir()
	name := "sh"
	if runtime.GOOS == "windows" {
		name = "cmd"
	}
	makeExec(t, shadow, name)
	p, err := Resolve(name, []string{shadow})
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(filepath.Dir(p), evalAbs(t, shadow)) {
		t.Errorf("run-path shadowed the fixed path: %s", p)
	}
}

func TestResolveRefusesPathsWithSeparators(t *testing.T) {
	dir := t.TempDir()
	makeExec(t, dir, "tool")
	bad := []string{"", "sub/tool", "./tool", "../tool", "a\x00b"}
	if runtime.GOOS == "windows" {
		bad = append(bad, `sub\tool`, `.\tool`, `C:tool`, `\tool`, `\\host\share\tool`, `//host/share/tool.exe`, "tool:stream")
	}
	for _, a := range bad {
		_, err := Resolve(a, []string{dir})
		if !errors.Is(err, ErrProgramNotFound) {
			t.Errorf("Resolve(%q) = %v, want program_not_found", a, err)
		}
	}
}

func TestResolveAbsolute(t *testing.T) {
	dir := t.TempDir()
	good := makeExec(t, dir, "tool")
	got, err := Resolve(good, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != evalAbs(t, good) {
		t.Errorf("got %s", got)
	}

	// A directory, a missing file and (where it matters) a file that is
	// not executable.
	cases := map[string]string{
		"directory": dir,
		"missing":   filepath.Join(dir, "nope.exe"),
	}
	plain := filepath.Join(dir, "data.txt")
	os.WriteFile(plain, []byte("x"), 0o644)
	cases["not executable"] = plain
	for name, p := range cases {
		if _, err := Resolve(p, nil); !errors.Is(err, ErrProgramNotFound) {
			t.Errorf("%s: err = %v, want program_not_found", name, err)
		}
	}
}

func TestResolveSymlinkIsResolved(t *testing.T) {
	dir := t.TempDir()
	target := makeExec(t, dir, "real")
	link := filepath.Join(dir, "link"+filepath.Ext(target))
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links not permitted here: %v", err)
	}
	got, err := Resolve(link, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != evalAbs(t, target) {
		t.Errorf("got %s, want %s", got, evalAbs(t, target))
	}
	// Bare name through a run-path link resolves too.
	got, err = Resolve("link", []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if got != evalAbs(t, target) {
		t.Errorf("bare: got %s", got)
	}
	// A link to a directory is not a program.
	dl := filepath.Join(dir, "dirlink.exe")
	if err := os.Symlink(t.TempDir(), dl); err == nil {
		if _, err := Resolve(dl, nil); !errors.Is(err, ErrProgramNotFound) {
			t.Errorf("link to directory: %v", err)
		}
	}
}
