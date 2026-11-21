//go:build windows

package run

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
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
// rule for ASCII; outside ASCII, by what the system's code page makes of
// the character (TestBatchPathTextCodePages).
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

	if windows.GetACP() != 1252 {
		t.Skipf("the working-folder case needs code page 1252 (this system: %d)", windows.GetACP())
	}
	bat = writeBatch(t, t.TempDir(), "t.cmd", "@echo off")
	p = prepare(t, bat)
	// U+FF02, a full-width quotation mark: code page 1252 turns it into ".
	dir := filepath.Join(t.TempDir(), "a"+string(rune(0xff02))+"b")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	spec = helperSpec(t, bat, "")
	spec.Dir = dir
	_, err := p.Start(spec)
	if !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), `the working folder holds a character that becomes " on this system`) {
		t.Errorf("folder: %v", err)
	}
}

// Outside ASCII, the path and working folder refuse a character only if
// the code page turns it into a refused byte (a DBCS second byte
// included), a backslash or a control character; one that becomes ? is
// fine. The code page is a parameter here: the system's can't be switched.
func TestBatchPathTextCodePages(t *testing.T) {
	u := func(rs ...rune) string { return string(rs) }
	ok := []struct {
		cp   uint32
		name string
		s    string
	}{
		{1252, "e acute, u umlaut", `C:` + backslash + "Users" + backslash + "Jos" + u(0xe9) + " Zo" + u(0xeb) + backslash + "npm"},
		{1252, "CJK becomes ?", "x" + u(0x4e2d) + "y"},
		{1252, "the replacement character becomes ?", "x" + u(0xfffd) + "y"},
		{1252, "outside the BMP", "x" + u(0x1f600) + "y"},
		{932, "e acute becomes e", "caf" + u(0xe9)},
		{932, "CJK in its own code page", u(0x4e2d, 0x6587)},
		{936, "CJK in its own code page", u(0x4e2d, 0x6587)},
		{65001, "UTF-8 gives no ASCII bytes", "a" + u(0xff02) + "b" + u(0xe9)},
	}
	for _, c := range ok {
		if err := batchPathTextCP(c.s, "the program's path", c.cp); err != nil {
			t.Errorf("cp%d %s: refused: %v", c.cp, c.name, err)
		}
	}
	refused := []struct {
		cp   uint32
		name string
		s    string
		want string
	}{
		{1252, "full-width quotation mark", "a" + u(0xff02) + "b", `becomes " on this system`},
		{1252, "full-width reverse solidus", "a" + u(0xff3c) + "b", `becomes ` + backslash + ` on this system`},
		{1252, "full-width percent sign", "a" + u(0xff05) + "b", "becomes % on this system"},
		{1252, "full-width ampersand", "a" + u(0xff06) + "b", "becomes & on this system"},
		{1252, "full-width vertical line", "a" + u(0xff5c) + "b", "becomes | on this system"},
		{1252, "full-width left parenthesis", "a" + u(0xff08) + "b", "becomes ( on this system"},
		{932, "yen sign", "a" + u(0xa5) + "b", `becomes ` + backslash + ` on this system`},
		{932, "DBCS second byte ^ (katakana TA)", "a" + u(0x30bf) + "b", "becomes ^ on this system"},
		{932, "DBCS second byte backslash (Cyrillic YERU)", "a" + u(0x042b) + "b", `becomes ` + backslash + ` on this system`},
		{936, "DBCS second byte backslash", "a" + u(0x4e57) + "b", `becomes ` + backslash + ` on this system`},
		{950, "DBCS second byte backslash", "a" + u(0x4e48) + "b", `becomes ` + backslash + ` on this system`},
		{1252, "an ASCII metacharacter still", "p(1)", "holds ("},
		{1252, "an ASCII control character still", "a" + u(9) + "b", "holds a control character"},
		{12345, "a code page that doesn't exist: the conversion fails", "caf" + u(0xe9), "can't convert"},
		{1252, "bytes that aren't UTF-8", "a" + string([]byte{0xff}) + "b", "can't convert"},
	}
	for _, c := range refused {
		err := batchPathTextCP(c.s, "the program's path", c.cp)
		if !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "the program's path holds") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("cp%d %s: %v (want %q)", c.cp, c.name, err, c.want)
		}
	}
	// Backslashes as separators and plain ASCII pass.
	if err := batchPathTextCP(`C:`+backslash+"x"+backslash+"y.cmd", "the program's path", 1252); err != nil {
		t.Errorf("an ASCII path: %v", err)
	}
}

// A batch file in a folder whose name is outside ASCII (an account name
// such as José), with that folder as the working folder, runs, and its
// arguments arrive whole. An argument outside ASCII is still refused
// (TestBatchArgumentRefused).
func TestBatchNonASCIIPathRuns(t *testing.T) {
	lookupOnly(t)
	if windows.GetACP() != 1252 {
		t.Skipf("needs code page 1252 (this system: %d)", windows.GetACP())
	}
	dir := filepath.Join(t.TempDir(), "Jos"+string(rune(0xe9))+" Zo"+string(rune(0xeb))+" "+string(rune(0x4e2d)), "npm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bat := writeBatch(t, dir, "t.cmd", "@echo off", "echo [%~1]", "exit /b 3")
	p := prepare(t, bat)
	spec := helperSpec(t, bat, "")
	spec.Argv = []string{bat, "plain ascii"}
	spec.Dir = evalAbs(t, dir)
	code, out := runOutput(t, p, spec)
	if code != 3 || out != "[plain ascii]"+crlf {
		t.Fatalf("exit %d, output %q", code, out)
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
	bat := filepath.Join(filepath.Dir(exe), "helper.cmd")
	if err := os.Rename(exe, bat); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(bat, ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "named as a batch file") {
		t.Fatalf("Prepare: %v", err)
	}
}

// A path with an 8.3 short name in it is not the held file's final name,
// so Prepare refuses it; Resolve gives the long name, which Prepare holds.
func TestShortNamePathResolvedFirst(t *testing.T) {
	lookupOnly(t)
	long := writeBatch(t, t.TempDir(), "a-long-batch-file-name.cmd", "@echo off")
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(windows.StringToUTF16Ptr(long), &buf[0], uint32(len(buf)))
	short := windows.UTF16ToString(buf[:n])
	if err != nil || short == long {
		t.Skipf("no 8.3 names on this volume: %v", err)
	}
	if _, err := Prepare(short, ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "link or junction") {
		t.Errorf("Prepare(short): %v", err)
	}
	resolved, err := Resolve(short, nil)
	if err != nil || resolved != long {
		t.Fatalf("Resolve(short) = %q, %v; want %q", resolved, err, long)
	}
	p, err := Prepare(resolved, "")
	if err != nil {
		t.Fatalf("Prepare(resolved): %v", err)
	}
	p.Close()
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

// A program reached through a junction above it is refused at the hold:
// the held file's final name must be the path.
func TestHoldThroughJunctionRefused(t *testing.T) {
	lookupOnly(t)
	real := t.TempDir()
	writeBatch(t, real, "t.cmd", "@echo off")
	helperCopy(t, real, "helper")
	link := filepath.Join(t.TempDir(), "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, real).CombinedOutput(); err != nil {
		t.Fatalf("can't make a junction: %v %s", err, out)
	}
	for _, name := range []string{"t.cmd", "helper.exe"} {
		if _, err := Prepare(filepath.Join(link, name), ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "through a link or junction") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Before a batch run resumes, its path must still name the held batch
// file: a path naming another file is refused and nothing runs.
func TestBatchPathRecheckedAtStart(t *testing.T) {
	lookupOnly(t)
	dir := t.TempDir()
	held := writeBatch(t, dir, "held.cmd", "@echo off")
	other := writeBatch(t, dir, "other.cmd", "@echo off", `echo x> "%~dp0marker"`)
	p := prepare(t, held)
	p.Path = other // as if the path now named another file
	spec := helperSpec(t, other, "")
	if _, err := p.Start(spec); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "no longer names the batch file") {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "marker")); err == nil {
		t.Fatal("the other batch ran")
	}
}

// When the user can make symbolic links, a batch file the user can
// change is refused, pinned or not; one only an administrator can change
// still runs, and without the capability the rule is the usual one.
func TestBatchSymlinkCapable(t *testing.T) {
	lookupOnly(t)
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off")
	old, oldCheck := symlinkCapable, checkProgram
	t.Cleanup(func() { symlinkCapable, checkProgram = old, oldCheck })
	userChangeable := func(p string) error {
		if p == bat {
			return errors.New("the user can change it")
		}
		return nil
	}
	symlinkCapable = func() (bool, error) { return true, nil }
	checkProgram = userChangeable
	if _, err := Prepare(bat, ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "symbolic links") {
		t.Errorf("capable, user-changeable: %v", err)
	}
	symlinkCapable = func() (bool, error) { return false, errors.New("unknown") }
	if _, err := Prepare(bat, ""); !errors.Is(err, ErrProgramNotFound) {
		t.Errorf("a failed check didn't refuse: %v", err)
	}
	checkProgram = func(string) error { return nil }
	symlinkCapable = func() (bool, error) { return true, nil }
	if p, err := Prepare(bat, ""); err != nil {
		t.Errorf("capable, admin-only: %v", err)
	} else {
		p.Close()
	}
	symlinkCapable = func() (bool, error) { return false, nil }
	checkProgram = userChangeable
	if p, err := Prepare(bat, ""); err != nil {
		t.Errorf("not capable: %v", err)
	} else {
		p.Close()
	}
}

// This machine's user (a standard user, Developer Mode off) can't make
// symbolic links: the check agrees with the system.
func TestCanCreateSymlinksAgrees(t *testing.T) {
	capable, err := canCreateSymlinks()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "l")
	made := os.Symlink(os.Args[0], link) == nil
	if made && !capable {
		t.Fatal("a symbolic link was made, but the check says this user can't make one")
	}
	t.Logf("can make symbolic links: %v (made one: %v)", capable, made)
}

// The minimal names copied from the connector's own environment are
// checked for a batch run too: whoever started the connector set them.
func TestBatchCopiedMinimalChecked(t *testing.T) {
	lookupOnly(t)
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off")
	p := prepare(t, bat)
	noStart(t)
	spec := helperSpec(t, bat, "")
	spec.Env = setVar(spec.Env, "USERPROFILE", `C:`+backslash+`a&b`)
	if _, err := p.Start(spec); !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "USERPROFILE") {
		t.Fatalf("Start: %v", err)
	}
}

// The secret reaches the program from its bytes; for a batch file, a
// value cmd.exe would read is refused with a message naming nothing of it.
func TestBatchSecret(t *testing.T) {
	lookupOnly(t)
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off", "echo [%MY_SECRET%]")
	p := prepare(t, bat)
	spec := helperSpec(t, bat, "")
	spec.Secret = &Secret{Name: "MY_SECRET", Value: []byte("plain-value-123")}
	code, out := runOutput(t, p, spec)
	if code != 0 || out != "[plain-value-123]"+crlf {
		t.Fatalf("exit %d, output %q", code, out)
	}

	p = prepare(t, bat)
	noStart(t)
	for _, v := range []string{"a&b", `pa"ss`, "x)", "100%", "end" + backslash, "caf" + string(rune(0xe9))} {
		spec.Secret = &Secret{Name: "MY_SECRET", Value: []byte(v)}
		_, err := p.Start(spec)
		if !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "how: file") {
			t.Errorf("%q: %v", v, err)
		}
		if err != nil && strings.Contains(err.Error(), v) {
			t.Errorf("the refusal repeats the value: %v", err)
		}
	}
}

// envBlock adds the secret from its bytes, in name order, replacing an
// entry of the same name.
func TestEnvBlockSecret(t *testing.T) {
	euro := string(rune(0x20ac))
	b, err := envBlock([]string{"Z=2", "s=old", "A=1"}, &Secret{Name: "S", Value: []byte("v" + euro)})
	if err != nil {
		t.Fatal(err)
	}
	nul := string(rune(0))
	if got, want := string(utf16.Decode(b)), "A=1"+nul+"S=v"+euro+nul+"Z=2"+nul+nul; got != want {
		t.Fatalf("block %q, want %q", got, want)
	}
}

// For a program, the secret arrives in its environment.
func TestStartSecretArrives(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	spec := helperSpec(t, exe, "env")
	spec.Secret = &Secret{Name: "MY_SECRET", Value: []byte("from-bytes")}
	code, out := runOutput(t, p, spec)
	if code != 0 || !strings.Contains(out, "MY_SECRET=from-bytes") {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

// The command line is exactly the planned one: /d, /e:on, /v:off, /s /c
// and the quotes.
func TestBatchCmdLineExact(t *testing.T) {
	q := `"`
	cmd := `C:` + backslash + `W` + backslash + `cmd.exe`
	bat := `C:` + backslash + `x` + backslash + `t.cmd`
	got := batchCmdLine(cmd, bat, []string{"a b", ""})
	want := q + cmd + q + ` /d /e:on /v:off /s /c ` + q + q + bat + q + ` ` + q + `a b` + q + ` ` + q + q + q
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// A working folder given as a network or device path is refused; for a
// batch file, so is a drive's root.
func TestStartRefusesDeviceAndRootCwd(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	noStart(t)
	b := backslash
	for _, dir := range []string{b + b + `?` + b + `C:` + b + `x`, b + `??` + b + `C:` + b + `x`, b + b + `server` + b + `share`, `//server/share`} {
		spec := helperSpec(t, exe, "")
		spec.Dir = dir
		if _, err := p.Start(spec); !errors.Is(err, ErrBadRequest) {
			t.Errorf("cwd %s: %v", dir, err)
		}
	}
	bat := writeBatch(t, t.TempDir(), "t.cmd", "@echo off")
	pb := prepare(t, bat)
	spec := helperSpec(t, bat, "")
	spec.Dir = filepath.VolumeName(bat) + b
	if _, err := pb.Start(spec); !errors.Is(err, ErrArgumentNotAllowed) || !strings.Contains(err.Error(), "root") {
		t.Errorf("root cwd: %v", err)
	}
}

// A program planted beside a batch file under its name plus a PATHEXT
// extension (foo.cmd.EXE, foo.cmd.COM) is not what cmd.exe runs: the
// batch file itself runs, and the planted programs never start.
func TestBatchPlantedExtensionsNotRun(t *testing.T) {
	lookupOnly(t)
	dir := t.TempDir()
	bat := writeBatch(t, dir, "foo.cmd", "@echo off", "echo [the batch ran]")
	marker := filepath.Join(t.TempDir(), "marker")
	for _, planted := range []string{"foo.cmd.EXE", "foo.cmd.COM"} {
		exe := helperCopy(t, dir, "planted")
		if err := os.Rename(exe, filepath.Join(dir, planted)); err != nil {
			t.Fatal(err)
		}
	}
	p := prepare(t, bat)
	spec := helperSpec(t, bat, "marker", Var{"VETTID_RUN_TEST_MARKER", marker})
	code, out := runOutput(t, p, spec)
	if code != 0 || out != "[the batch ran]"+crlf {
		t.Fatalf("exit %d, output %q", code, out)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a planted program ran")
	}
	// The control: run directly, a planted program does leave the marker.
	c := exec.Command(filepath.Join(dir, "foo.cmd.EXE"))
	c.Env = append(os.Environ(), helperVar+"=marker", "VETTID_RUN_TEST_MARKER="+marker)
	if err := c.Run(); err != nil {
		t.Fatalf("the planted program can't be run directly: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the planted program run directly left no marker, so the check above shows nothing: %v", err)
	}
}

// The block is allocated once: a large environment after the secret's
// entry doesn't make it grow (which could leave a copy of the secret).
func TestEnvBlockOneAllocation(t *testing.T) {
	env := []string{"A=1"}
	for i := 0; i < 200; i++ {
		env = append(env, "Z"+strings.Repeat("Z", i%60)+"=value-"+strings.Repeat("v", 100))
	}
	b, err := envBlock(env, &Secret{Name: "B", Value: []byte("s3cr3t" + string(rune(0x1f600)))})
	if err != nil {
		t.Fatal(err)
	}
	if cap(b) != len(b) {
		t.Fatalf("the block grew past its first allocation: len %d, cap %d", len(b), cap(b))
	}
}

// A secret that is not valid UTF-8, or holds a NUL, is refused, not
// delivered changed.
func TestStartRefusesABadSecret(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	noStart(t)
	for _, v := range [][]byte{{'a', 0xff, 'b'}, {'a', 0, 'b'}} {
		spec := helperSpec(t, exe, "")
		spec.Secret = &Secret{Name: "MY_SECRET", Value: v}
		if _, err := p.Start(spec); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%q: %v", v, err)
		}
	}
}
