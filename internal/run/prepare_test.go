package run

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The test binary doubles as the program a run starts: with
// VETTID_RUN_TEST_HELPER set in its environment it does one thing and
// exits instead of running the tests.
const helperVar = "VETTID_RUN_TEST_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(helperVar) {
	case "":
		os.Exit(m.Run())
	case "env":
		for _, kv := range os.Environ() {
			fmt.Println(kv)
		}
		os.Exit(0)
	case "exe":
		// The started image as the system names it.
		if runtime.GOOS == "linux" {
			p, err := os.Readlink("/proc/self/exe")
			if err != nil {
				os.Exit(3)
			}
			fmt.Println(p)
		} else {
			p, _ := os.Executable()
			fmt.Println(p)
		}
		os.Exit(0)
	case "marker":
		os.WriteFile(os.Getenv("VETTID_RUN_TEST_MARKER"), []byte("ran"), 0o600)
		os.Exit(0)
	case "args":
		for _, a := range os.Args[1:] {
			fmt.Printf("%q\n", a)
		}
		os.Exit(0)
	case "exit7":
		os.Exit(7)
	default:
		if platformHelper(os.Getenv(helperVar)) {
			os.Exit(0)
		}
		os.Exit(2)
	}
}

// helperCopy copies the test binary to dir/name (with .exe on Windows) and
// returns its path with links resolved.
func helperCopy(t *testing.T, dir, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dst := filepath.Join(dir, name)
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return evalAbs(t, dst)
}

// binDir is the per-run folder for the macOS copy (unused elsewhere).
func binDir(t *testing.T) string { return filepath.Join(t.TempDir(), "bin") }

func prepare(t *testing.T, path string) *Program {
	t.Helper()
	p, err := Prepare(path, binDir(t))
	if err != nil {
		t.Fatalf("Prepare(%s): %v", path, err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// helperSpec is a StartSpec for the helper in mode, with the run's env
// built by Env and extra request variables.
func helperSpec(t *testing.T, argv0, mode string, extra ...Var) StartSpec {
	t.Helper()
	req := append([]Var{{helperVar, mode}}, extra...)
	var listed []string
	for _, v := range req {
		listed = append(listed, v.Name)
	}
	env, err := Env(Spec{Tmp: t.TempDir(), Listed: listed, Request: req}, os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	return StartSpec{Argv: []string{argv0}, Env: env, Dir: t.TempDir()}
}

// runOutput starts p as spec says, with standard output to a file, waits
// and returns the exit code and the output.
func runOutput(t *testing.T, p *Program, spec StartSpec) (int, string) {
	t.Helper()
	out, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	spec.Stdout = out
	proc, err := p.Start(spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	code, err := proc.Wait()
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	b, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return code, string(b)
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// The hash is the file's SHA-256, lowercase hex, and the program runs.
func TestPrepareHashesAndRuns(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	if want := sha256File(t, exe); p.SHA256 != want {
		t.Fatalf("SHA256 = %s, want %s", p.SHA256, want)
	}
	if len(p.SHA256) != 64 || strings.ToLower(p.SHA256) != p.SHA256 {
		t.Fatalf("SHA256 %q is not 64 lowercase hex digits", p.SHA256)
	}
	if p.Path != exe {
		t.Fatalf("Path = %s", p.Path)
	}
	proc, err := p.Start(helperSpec(t, exe, "exit7"))
	if err != nil {
		t.Fatal(err)
	}
	if code, err := proc.Wait(); err != nil || code != 7 {
		t.Fatalf("exit %d, %v; want 7", code, err)
	}
}

// A file that starts with #! is refused on every platform.
func TestPrepareRefusesAScript(t *testing.T) {
	name := "tool"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Prepare(evalAbs(t, p), binDir(t))
	if !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "script") {
		t.Fatalf("script: %v, want program_not_found for a script", err)
	}
	// "#" alone, or "#!" further in, is not a script.
	if err := os.WriteFile(p, []byte("# not!#!"), 0o755); err != nil {
		t.Fatal(err)
	}
	q, err := Prepare(evalAbs(t, p), binDir(t))
	if err != nil {
		t.Fatalf("not a script: %v", err)
	}
	q.Close()
}

func TestPrepareRefusesWhatIsNotAProgram(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{evalAbs(t, dir), evalAbs(t, plain), filepath.Join(evalAbs(t, dir), "missing.exe"), "relative.exe", ""} {
		if _, err := Prepare(p, binDir(t)); !errors.Is(err, ErrProgramNotFound) {
			t.Errorf("Prepare(%q) = %v, want program_not_found", p, err)
		}
	}
}

// Just before the start argv[0] is resolved again: a program put earlier
// on the search path since refuses the run.
func TestStartRefusesAChangedResolution(t *testing.T) {
	lookupOnly(t)
	first, second := t.TempDir(), t.TempDir()
	exe := helperCopy(t, second, "vettidtesttool")
	runPath := []string{evalAbs(t, first), evalAbs(t, second)}
	got, err := Resolve("vettidtesttool", runPath)
	if err != nil || got != exe {
		t.Fatalf("Resolve = %s, %v", got, err)
	}
	p := prepare(t, got)
	helperCopy(t, first, "vettidtesttool") // now found first
	spec := helperSpec(t, "vettidtesttool", "exit7")
	spec.RunPath = runPath
	if _, err := p.Start(spec); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "now resolves") {
		t.Fatalf("changed resolution: %v, want program_not_found", err)
	}
}

// The pin fallback: a program the connector's user can change is refused,
// unless it is exactly the catalog's pinned path.
func TestResolvePinnedSkipsTheCheckForThePinnedPathOnly(t *testing.T) {
	plainOnly(t)
	own := makeExec(t, t.TempDir(), "ktool")
	real := evalAbs(t, own)
	if _, err := Resolve(real, nil); !errors.Is(err, ErrProgramNotFound) {
		t.Fatalf("unpinned changeable program: %v", err)
	}
	got, err := ResolvePinned(real, nil, real)
	if err != nil || got != real {
		t.Fatalf("pinned: %s, %v", got, err)
	}
	// The comparison is exact, on Windows too: another case, or a
	// character that only folds to the same one (the Kelvin sign for k),
	// is another path.
	if _, err := ResolvePinned(real, nil, strings.ToUpper(real)); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("pinned, other case: %v", err)
	}
	kelvin := strings.Replace(real, "ktool", string(rune(0x212A))+"tool", 1)
	if kelvin == real || !strings.EqualFold(kelvin, real) {
		t.Fatalf("test setup: %q", kelvin)
	}
	if _, err := ResolvePinned(real, nil, kelvin); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("pinned with a Kelvin sign: %v", err)
	}
	// Moved, or copied, elsewhere: checked again.
	moved := makeExec(t, t.TempDir(), "ktool")
	if _, err := ResolvePinned(evalAbs(t, moved), nil, real); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("program away from its pinned path: %v", err)
	}
	// No pin matches nothing.
	if _, err := ResolvePinned(real, nil, ""); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("empty pin: %v", err)
	}
	// A bare name found on the run path at its pinned path.
	dir := filepath.Dir(real)
	got, err = ResolvePinned("ktool", []string{dir}, real)
	if err != nil || got != real {
		t.Errorf("bare name at its pinned path: %s, %v", got, err)
	}
}

// The pinned path still gets the path rules (reparse points, drives).
func TestResolvePinnedKeepsThePathRules(t *testing.T) {
	old := checkPlain
	checkPlain = func(string) error { return errors.New("is a junction") }
	t.Cleanup(func() { checkPlain = old })
	real := evalAbs(t, makeExec(t, t.TempDir(), "tool"))
	if _, err := ResolvePinned(real, nil, real); !errors.Is(err, ErrProgramNotFound) {
		t.Fatalf("pinned path failing the path rules: %v", err)
	}
}

// plainOnly leaves checkProgram real but lets the user's own temporary
// folders pass the path rules (they hold no reparse points, but CI's
// temporary folder might sit on one).
func plainOnly(t *testing.T) {
	t.Helper()
	old := checkPlain
	checkPlain = func(string) error { return nil }
	t.Cleanup(func() { checkPlain = old })
}

func TestCheckEnvAllowed(t *testing.T) {
	listed := []string{"MY_TOKEN_USER", "REGION", "NODE_OPTIONS"}
	if err := CheckEnvAllowed(listed, []Var{{"REGION", "eu"}, {"MY_TOKEN_USER", "x"}}); err != nil {
		t.Fatalf("listed names: %v", err)
	}
	if err := CheckEnvAllowed(nil, nil); err != nil {
		t.Fatalf("no env: %v", err)
	}
	err := CheckEnvAllowed(listed, []Var{{"REGION", "eu"}, {"OTHER", "1"}, {"MORE", "2"}, {"OTHER", "3"}})
	var e *Error
	if !errors.Is(err, ErrEnvNotAllowed) || !errors.As(err, &e) || strings.Join(e.Names, ",") != "OTHER,MORE" {
		t.Fatalf("unlisted names: %v (%+v)", err, e)
	}
	// An unbound item, or an entry with no names: any env is refused.
	if err := CheckEnvAllowed(nil, []Var{{"REGION", "eu"}}); !errors.Is(err, ErrEnvNotAllowed) {
		t.Fatalf("no list: %v", err)
	}
	// A code-loading name is refused even when listed, by the name rule,
	// before the allowlist.
	if err := CheckEnvAllowed(listed, []Var{{"NODE_OPTIONS", "--require x"}}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("listed code-loading name: %v, want bad_request", err)
	}
	if err := CheckEnvAllowed(listed, []Var{{"OTHER", "1"}, {"NODE_OPTIONS", "x"}}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("name rule before allowlist: %v, want bad_request", err)
	}
	// No value is carried in the error.
	err = CheckEnvAllowed(listed, []Var{{"OTHER", "s3cr3t-value"}})
	if err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("error text: %v", err)
	}
	if got := UnlistedEnv([]string{"A"}, []Var{{"A", ""}, {"B", ""}}); len(got) != 1 || got[0] != "B" {
		t.Fatalf("UnlistedEnv = %v", got)
	}
	// Env's own checks come first, as bad_request, even for unlisted
	// names: the count, a value's length and a NUL byte.
	var many []Var
	for i := 0; i <= MaxRequestEnv; i++ {
		many = append(many, Var{fmt.Sprintf("V%d", i), "x"})
	}
	for name, req := range map[string][]Var{
		"too many":      many,
		"too long":      {{"REGION", strings.Repeat("x", MaxEnvValueLen+1)}},
		"NUL byte":      {{"REGION", "a\x00b"}},
		"unlisted, NUL": {{"OTHER", "a\x00b"}},
	} {
		if err := CheckEnvAllowed(listed, req); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: %v, want bad_request", name, err)
		}
	}
	if err := CheckEnvAllowed(listed, []Var{{"REGION", strings.Repeat("x", MaxEnvValueLen)}}); err != nil {
		t.Errorf("value at the limit: %v", err)
	}
}
