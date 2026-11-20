//go:build windows

package run

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	crlf      = string(rune(13)) + string(rune(10))
	backslash = string(rune(92))
)

// writeBatch writes a batch file of lines in dir.
func writeBatch(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(strings.Join(lines, crlf)+crlf), 0o600); err != nil {
		t.Fatal(err)
	}
	return evalAbs(t, p)
}

// noStart fails the test if Start creates a process.
func noStart(t *testing.T) {
	t.Helper()
	startHook = func(stage string) { t.Errorf("a process was %s", stage) }
	t.Cleanup(func() { startHook = nil })
}

// Every character cmd.exe reads as a command, each control character,
// a character outside ASCII (a best-fit lookalike of " among them) and a
// trailing backslash are refused in an argument, before anything starts.
func TestBatchArgumentRefused(t *testing.T) {
	lookupOnly(t)
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off", "echo %~1")
	p := prepare(t, bat)
	noStart(t)
	cases := map[string]string{
		"ampersand":            "a&echo x",
		"pipe":                 "a|b",
		"less":                 "a<b",
		"greater":              "a>b",
		"caret":                "a^b",
		"open paren":           "a(b",
		"close paren":          "a)b",
		"percent":              "%PATH%",
		"bang":                 "a!b",
		"quote":                `a"b`,
		"carriage return":      "a" + string(rune(13)) + "b",
		"line feed":            "a" + string(rune(10)) + "b",
		"tab":                  "a" + string(rune(9)) + "b",
		"DEL":                  "a" + string(rune(0x7f)) + "b",
		"trailing backslash":   "dir" + backslash,
		"fullwidth quote":      "a" + string(rune(0xff02)) + "b",
		"yen sign":             "a" + string(rune(0xa5)) + "b",
		"letter outside ASCII": "caf" + string(rune(0xe9)),
	}
	for name, arg := range cases {
		spec := helperSpec(t, bat, "")
		spec.Argv = []string{bat, "fine", arg}
		_, err := p.Start(spec)
		if !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "argument 2") {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), arg) && len(arg) > 1 {
			t.Errorf("%s: the refusal repeats the argument: %v", name, err)
		}
	}
}

// The batch file's path and the working folder are checked by the same
// rule.
func TestBatchPathAndFolderRefused(t *testing.T) {
	lookupOnly(t)
	odd := filepath.Join(t.TempDir(), "p(1)")
	if err := os.Mkdir(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	bat := writeBatch(t, odd, "t.cmd", "@echo off")
	p := prepare(t, bat)
	noStart(t)
	spec := helperSpec(t, bat, "")
	if _, err := p.Start(spec); !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "the program's path") {
		t.Errorf("path: %v", err)
	}

	bat = writeBatch(t, t.TempDir(), "t.cmd", "@echo off")
	p = prepare(t, bat)
	dir := filepath.Join(t.TempDir(), "caf"+string(rune(0xe9)))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	spec = helperSpec(t, bat, "")
	spec.Dir = dir
	if _, err := p.Start(spec); !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "the working folder") {
		t.Errorf("folder: %v", err)
	}
}

// A batch file runs through cmd.exe: arguments with spaces and cmd.exe's
// separators arrive whole, an empty one too, and the started image is
// System32's cmd.exe.
func TestBatchRuns(t *testing.T) {
	lookupOnly(t)
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off", "echo [%~1]", "echo [%~2]", "echo [%~3]", "echo [%~4]", "exit /b 7")
	p := prepare(t, bat)
	spec := helperSpec(t, bat, "")
	spec.Argv = []string{bat, "a b", "semi;comma,eq=x", "", `C:` + backslash + "x"}
	code, out := runOutput(t, p, spec)
	if code != 7 {
		t.Fatalf("exit %d, output %q", code, out)
	}
	want := "[a b]" + crlf + "[semi;comma,eq=x]" + crlf + "[]" + crlf + "[C:" + backslash + "x]" + crlf
	if out != want {
		t.Fatalf("output %q, want %q", out, want)
	}
}

// The image check expects cmd.exe: if the held cmd.exe's identity is not
// the started image's, the run is refused and the batch never runs.
func TestBatchImageIsCmd(t *testing.T) {
	lookupOnly(t)
	dir := t.TempDir()
	bat := writeBatch(t, dir, "t.cmd", "@echo off", `echo x> "%~dp0marker"`)
	p := prepare(t, bat)
	p.plat.cmdID = p.plat.id // as if another file had been started
	spec := helperSpec(t, bat, "")
	if _, err := p.Start(spec); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "is not the file that was checked") {
		t.Fatalf("another image: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "marker")); err == nil {
		t.Fatal("the refused batch ran")
	}
}

// The batch file stays held, unchangeable, for the whole run, even after
// the Program is closed, and is released when the process has ended.
func TestBatchHeldForTheRun(t *testing.T) {
	lookupOnly(t)
	dir := t.TempDir()
	bat := writeBatch(t, dir, "t.cmd", "@echo off", ":loop", `if not exist "%~dp0go" goto loop`, "exit /b 0")
	p := prepare(t, bat)
	proc, err := p.Start(helperSpec(t, bat, ""))
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if f, err := os.OpenFile(bat, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Error("the batch file could be opened for writing while it ran")
	}
	if err := os.Rename(bat, bat+".moved"); err == nil {
		t.Error("the batch file could be renamed while it ran")
	}
	if err := os.WriteFile(filepath.Join(dir, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, err := proc.Wait(); err != nil || code != 0 {
		t.Fatalf("exit %d, %v", code, err)
	}
	f, err := os.OpenFile(bat, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("the batch file is still held after the run: %v", err)
	}
	f.Close()
}

// A batch file that is a Windows program is refused.
func TestBatchThatIsAProgram(t *testing.T) {
	lookupOnly(t)
	dir := t.TempDir()
	exe := helperCopy(t, dir, "helper")
	bat := filepath.Join(dir, "helper.cmd")
	if err := os.Rename(exe, bat); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(bat, ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "named as a batch file") {
		t.Fatalf("Prepare: %v", err)
	}
}

// cmd.exe's own limit on a command line (8,191 characters) applies.
func TestBatchCommandLineLimit(t *testing.T) {
	lookupOnly(t)
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off")
	p := prepare(t, bat)
	noStart(t)
	spec := helperSpec(t, bat, "")
	spec.Argv = []string{bat}
	for i := 0; i < 90; i++ {
		spec.Argv = append(spec.Argv, strings.Repeat("x", 100))
	}
	if _, err := p.Start(spec); !errors.Is(err, ErrBadRequest) || !strings.Contains(err.Error(), "8191") {
		t.Fatalf("Start: %v", err)
	}
}

// npm's shims: an extensionless path to a file that is not a Windows
// program, with <name>.cmd beside it, resolves to the .cmd. Only .cmd is
// tried: a .bat or .ps1 beside it is not picked up, nor is a .cmd beside a
// Windows program. A bare name finds a batch file only by its extension.
func TestBatchShim(t *testing.T) {
	lookupOnly(t)
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	eslint := write("eslint", "#!/bin/sh"+crlf+"exec node eslint.js"+crlf)
	write("eslint.cmd", "@echo off"+crlf)
	got, err := Resolve(eslint, nil)
	if err != nil || !samePath(got, evalAbs(t, eslint+".cmd")) {
		t.Fatalf("shim: %q, %v", got, err)
	}

	tool := write("tool", "#!/bin/sh"+crlf)
	write("tool.bat", "@echo off"+crlf)
	write("tool.ps1", "exit 0"+crlf)
	if got, err := Resolve(tool, nil); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("a .bat or .ps1 beside it was picked up: %q, %v", got, err)
	}

	prog := write("prog", "MZ")
	write("prog.cmd", "@echo off"+crlf)
	if got, err := Resolve(prog, nil); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("a .cmd beside a Windows program was picked up: %q, %v", got, err)
	}

	if got, err := Resolve("eslint.cmd", []string{evalAbs(t, dir)}); err != nil || !samePath(got, evalAbs(t, eslint+".cmd")) {
		t.Errorf("bare name with .cmd: %q, %v", got, err)
	}
	if got, err := Resolve("tool", []string{evalAbs(t, dir)}); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("a bare name found a batch file without its extension: %q, %v", got, err)
	}
}

// The value of every environment variable the agent controls is checked
// as an argument is (cmd.exe expands %NAME% before it parses a line); a
// variable named as one of cmd.exe's own is refused whoever set it. The
// connector's own variables and the trusted ones (the secret's, the
// operator's) are not checked by value.
func TestBatchEnvironment(t *testing.T) {
	lookupOnly(t)
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off", `findstr /? >nul "%MYOPT%"`)
	p := prepare(t, bat)
	noStart(t)
	for name, v := range map[string]string{
		"quote and ampersand": `x" & whoami & "`,
		"percent":             "%PATH%",
		"trailing backslash":  "dir" + backslash,
		"outside ASCII":       "caf" + string(rune(0xe9)),
	} {
		spec := helperSpec(t, bat, "", Var{"MYOPT", v})
		_, err := p.Start(spec)
		if !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "the environment variable MYOPT") {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), v) {
			t.Errorf("%s: the refusal repeats the value: %v", name, err)
		}
	}
	for _, n := range []string{"ERRORLEVEL", "cd", "CMDCMDLINE"} {
		spec := helperSpec(t, bat, "")
		spec.Env = append(spec.Env, n+"=1")
		spec.Trusted = []string{n}
		if _, err := p.Start(spec); !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "one cmd.exe sets itself") {
			t.Errorf("%s: %v", n, err)
		}
	}
	startHook = nil
	spec := helperSpec(t, bat, "")
	spec.Env = append(spec.Env, `SECRET=pa%ss&wo"rd`)
	spec.Trusted = []string{"SECRET"}
	proc, err := p.Start(spec)
	if err != nil {
		t.Fatalf("a trusted variable was checked: %v", err)
	}
	proc.Wait()
}

// Kill releases the held batch file once the process has ended, even
// without Wait.
func TestBatchKillReleases(t *testing.T) {
	lookupOnly(t)
	dir := t.TempDir()
	bat := writeBatch(t, dir, "t.cmd", "@echo off", ":loop", "goto loop")
	p := prepare(t, bat)
	proc, err := p.Start(helperSpec(t, bat, ""))
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	if err := proc.Kill(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(bat, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("the batch file is still held after Kill: %v", err)
	}
	f.Close()
	proc.Wait()
}
