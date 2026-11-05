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

// lookupOnly lets a test check the lookup order with programs in its own
// temporary directories, which the at-every-run rule would refuse.
func lookupOnly(t *testing.T) {
	t.Helper()
	old := checkProgram
	checkProgram = func(string) error { return nil }
	t.Cleanup(func() { checkProgram = old })
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
	lookupOnly(t)
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
	if !inFixed {
		t.Errorf("%s resolved to %s, outside the fixed path", sys, p)
	}
}

func TestResolveFixedBeforeRunPath(t *testing.T) {
	lookupOnly(t)
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
	lookupOnly(t)
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
	lookupOnly(t)
	dir := t.TempDir()
	target := makeExec(t, dir, "real")
	// A name no system has on its fixed path.
	link := filepath.Join(dir, "vettidtestlink"+filepath.Ext(target))
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
	got, err = Resolve("vettidtestlink", []string{dir})
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

// The owner's rule at every run (2026-11-05): a program the connector's
// user can change, or under a folder it can change, isn't run.
func TestResolveRefusesAChangeableProgram(t *testing.T) {
	own := makeExec(t, t.TempDir(), "tool") // the user's own file and folder
	if _, err := Resolve(own, nil); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "can be changed") {
		t.Fatalf("user-owned program: %v", err)
	}
	// A link from elsewhere to it: the target is what's checked.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(own, link); err == nil {
		if _, err := Resolve(link, nil); !errors.Is(err, ErrProgramNotFound) {
			t.Errorf("link to a user-owned program: %v", err)
		}
	}
	// A system program is run (not as an administrator, where every
	// folder can be changed and nothing is run).
	skipIfElevated(t)
	sys := "/bin/sh"
	if runtime.GOOS == "windows" {
		sys = filepath.Join(FixedPath()[0], "cmd.exe")
	}
	if _, err := Resolve(sys, nil); err != nil {
		t.Errorf("%s: %v", sys, err)
	}
}

// The fixed path itself gets the rule: a user-owned directory on it (as
// Homebrew's /opt/homebrew/bin is) doesn't supply programs.
func TestResolveRefusesAUserOwnedFixedPathDirectory(t *testing.T) {
	dir := t.TempDir()
	makeExec(t, dir, "brewtool")
	old := fixedPath
	fixedPath = func() []string { return []string{dir} }
	t.Cleanup(func() { fixedPath = old })
	if _, err := Resolve("brewtool", nil); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "can be changed") {
		t.Fatalf("user-owned fixed-path directory: %v", err)
	}
}

// A protected file under a folder the user can change is refused for the
// folder (POSIX: a read-only program in the user's own directory).
func TestResolveRefusesAChangeableFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows the user's own file is already refused for itself")
	}
	dir := t.TempDir()
	p := makeExec(t, dir, "tool")
	if err := os.Chmod(p, 0o555); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(p, nil)
	if !errors.Is(err, ErrProgramNotFound) {
		t.Fatalf("program under a user-owned folder: %v", err)
	}
}
