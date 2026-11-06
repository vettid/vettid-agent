//go:build windows

package run

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// While the program is held, it can't be written to, renamed or deleted.
func TestPrepareHoldsTheFile(t *testing.T) {
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	if f, err := os.OpenFile(exe, os.O_WRONLY, 0); err == nil {
		f.Close()
		t.Error("opened for writing while held")
	}
	if err := os.WriteFile(exe, []byte("MZ swapped"), 0o755); err == nil {
		t.Error("written while held")
	}
	if err := os.Rename(exe, exe+".old"); err == nil {
		t.Error("renamed while held")
	}
	if err := os.Remove(exe); err == nil {
		t.Error("deleted while held")
	}
	// Reading stays allowed (another run of the same program).
	q, err := Prepare(exe, "")
	if err != nil {
		t.Fatalf("a second hold: %v", err)
	}
	q.Close()
	p.Close()
	if err := os.Rename(exe, exe+".old"); err != nil {
		t.Errorf("rename after Close: %v", err)
	}
}

// Renaming a folder above a held program: AGENT-PLAN §4.9 leaves this to
// be confirmed. The result is logged as Windows gave it. If the rename
// goes through, a file put at the old path in its place must be refused
// at the image check.
func TestHeldProgramParentRename(t *testing.T) {
	lookupOnly(t)
	root := evalAbs(t, t.TempDir())
	parent := filepath.Join(root, "a")
	if err := os.MkdirAll(filepath.Join(parent, "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	exe := helperCopy(t, filepath.Join(parent, "b"), "helper")
	p := prepare(t, exe)
	for _, dir := range []string{filepath.Join(parent, "b"), parent} {
		moved := dir + "-moved"
		err := os.Rename(dir, moved)
		if err != nil {
			t.Logf("renaming the folder %s above a held program: refused: %v", strings.TrimPrefix(dir, root), err)
			continue
		}
		t.Logf("renaming the folder %s above a held program: allowed", strings.TrimPrefix(dir, root))
		// A different file at the old path.
		if err := os.MkdirAll(filepath.Dir(exe), 0o700); err != nil {
			t.Fatal(err)
		}
		helperCopy(t, filepath.Dir(exe), "helper")
		_, err = p.Start(helperSpec(t, exe, "exit7"))
		if !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "is not the file that was checked") {
			t.Fatalf("swapped file after a folder rename: %v, want a refusal at the image check", err)
		}
		return
	}
	// Both refused: the hold is the reason, so once it's released the
	// same rename goes through.
	p.Close()
	if err := os.Rename(parent, parent+"-moved"); err != nil {
		t.Fatalf("renaming %s after the hold was released: %v (so the refusal above was not the hold's)", strings.TrimPrefix(parent, root), err)
	}
	t.Logf("renaming the folder \\a after the hold was released: allowed")
}

// The image check refuses a started image that is not the held file,
// whatever the rename result above: a program held for one file and
// started from another path.
func TestStartRefusesAnotherImage(t *testing.T) {
	lookupOnly(t)
	held := helperCopy(t, t.TempDir(), "held")
	other := helperCopy(t, t.TempDir(), "other")
	p := prepare(t, held)
	p.Path = other // as if the path now named another file
	marker := filepath.Join(t.TempDir(), "marker")
	spec := helperSpec(t, other, "marker", Var{"VETTID_RUN_TEST_MARKER", marker})
	_, err := p.Start(spec)
	if !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "is not the file that was checked") {
		t.Fatalf("another image: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the refused process ran")
	}
}

// A file another process has open for writing is refused: the open with
// read-only sharing fails. (A handle of this process stands for it: the
// sharing rule is per handle, whichever process holds it.)
func TestPrepareRefusesAFileOpenForWriting(t *testing.T) {
	exe := helperCopy(t, t.TempDir(), "helper")
	w, err := os.OpenFile(exe, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := Prepare(exe, ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "open for writing") {
		t.Fatalf("file open for writing: %v", err)
	}
}

// Only NTFS and ReFS volumes.
func TestAllowedFileSystem(t *testing.T) {
	for fs, ok := range map[string]bool{"NTFS": true, "ReFS": true, "refs": true, "FAT": false, "FAT32": false, "exFAT": false, "UDF": false, "CDFS": false, "": false} {
		if allowedFileSystem(fs) != ok {
			t.Errorf("allowedFileSystem(%q) = %v", fs, !ok)
		}
	}
}

// A program on a FAT or exFAT volume is refused. Making such a volume
// (a virtual disk) needs an administrator, so this uses one only when the
// machine already has a writable one.
func TestPrepareRefusesAFATVolume(t *testing.T) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		r16, _ := windows.UTF16PtrFromString(root)
		var fsName [windows.MAX_PATH + 1]uint16
		if windows.GetVolumeInformation(r16, nil, 0, nil, nil, nil, &fsName[0], uint32(len(fsName))) != nil {
			continue
		}
		fs := windows.UTF16ToString(fsName[:])
		if !strings.HasPrefix(strings.ToUpper(fs), "FAT") && !strings.EqualFold(fs, "exFAT") {
			continue
		}
		dir, err := os.MkdirTemp(root, "vettid-run-test-")
		if err != nil {
			continue
		}
		t.Cleanup(func() { os.RemoveAll(dir) })
		exe := filepath.Join(dir, "tool.exe")
		if err := os.WriteFile(exe, []byte("MZ not really a program"), 0o755); err != nil {
			continue
		}
		if _, err := Prepare(exe, ""); !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "NTFS or ReFS") {
			t.Fatalf("program on %s (%s): %v", root, fs, err)
		}
		return
	}
	t.Skip("no writable FAT or exFAT volume on this machine, and making one (a virtual disk) needs an administrator")
}

// cmd.exe from the fixed path is held and started as itself.
func TestStartSystemProgram(t *testing.T) {
	lookupOnly(t)
	cmd, err := Resolve("cmd", nil)
	if err != nil {
		t.Fatal(err)
	}
	p := prepare(t, cmd)
	spec := helperSpec(t, "cmd", "")
	spec.Argv = []string{"cmd", "/c", "exit 3"}
	proc, err := p.Start(spec)
	if err != nil {
		t.Fatal(err)
	}
	if code, err := proc.Wait(); err != nil || code != 3 {
		t.Fatalf("cmd /c exit 3: %d, %v", code, err)
	}
}

// The process is created suspended, checked, then resumed: at the check
// it has not run.
func TestStartChecksBeforeResume(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	marker := filepath.Join(t.TempDir(), "marker")
	var stages []string
	startHook = func(stage string) {
		stages = append(stages, stage)
		if stage == "checked" {
			time.Sleep(300 * time.Millisecond)
			if _, err := os.Stat(marker); err == nil {
				t.Error("the process ran before it was resumed")
			}
		}
	}
	t.Cleanup(func() { startHook = nil })
	proc, err := p.Start(helperSpec(t, exe, "marker", Var{"VETTID_RUN_TEST_MARKER", marker}))
	if err != nil {
		t.Fatal(err)
	}
	if code, err := proc.Wait(); err != nil || code != 0 {
		t.Fatalf("exit %d, %v", code, err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the process didn't run after the resume: %v", err)
	}
	if strings.Join(stages, ",") != "created,checked,resumed" {
		t.Fatalf("stages %v", stages)
	}
}

// The child's environment is the one given, with
// NoDefaultCurrentDirectoryInExePath=1; nothing else is inherited.
func TestStartEnvironment(t *testing.T) {
	lookupOnly(t)
	t.Setenv("VETTID_RUN_TEST_INHERITED", "1")
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	spec := helperSpec(t, exe, "env")
	// A request can't turn it off.
	spec.Env = append(spec.Env, "NODEFAULTCURRENTDIRECTORYINEXEPATH=")
	code, out := runOutput(t, p, spec)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	var found int
	for _, l := range lines {
		k, v, _ := strings.Cut(l, "=")
		if strings.EqualFold(k, noCwdExeName) {
			found++
			if v != "1" {
				t.Errorf("%s", l)
			}
		}
		if k == "VETTID_RUN_TEST_INHERITED" {
			t.Errorf("inherited %s", k)
		}
	}
	if found != 1 {
		t.Fatalf("%s present %d times in:\n%s", noCwdExeName, found, out)
	}
}

// The command line is quoted for CreateProcess: arguments with spaces,
// quotes and backslashes arrive as given.
func TestStartArguments(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	args := []string{"a b", `c"d`, `e\`, `f\\"g`, "", `C:\Program Files\x\`, "%PATH%", "&|<>^"}
	spec := helperSpec(t, exe, "args")
	spec.Argv = append([]string{exe}, args...)
	code, out := runOutput(t, p, spec)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var want strings.Builder
	for _, a := range args {
		fmt.Fprintf(&want, "%q\n", a)
	}
	if got := strings.ReplaceAll(out, "\r\n", "\n"); got != want.String() {
		t.Fatalf("arguments arrived as\n%s\nwant\n%s", got, want.String())
	}
}

// The image check reads the native image path and reopens it through
// \\?\GLOBALROOT, with no drive letter: for this process, that names the
// same file as its drive-letter path.
func TestNativeImagePathReopens(t *testing.T) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(windows.CurrentProcess(), windows.PROCESS_NAME_NATIVE, &buf[0], &n); err != nil {
		t.Fatal(err)
	}
	native := windows.UTF16ToString(buf[:n])
	if !strings.HasPrefix(native, `\Device\`) {
		t.Fatalf("native image path %q", native)
	}
	open := func(p string) fileIdentity {
		t.Helper()
		p16, _ := windows.UTF16PtrFromString(p)
		h, err := windows.CreateFile(p16, windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			t.Fatalf("open %s: %v", p, err)
		}
		defer windows.CloseHandle(h)
		id, _, err := identityOf(h)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if !open(globalRoot + native).same(open(self)) {
		t.Fatalf("%s through GLOBALROOT is not %s", native, self)
	}
	t.Logf("native image path reopened through GLOBALROOT: %s", native)
}

// The start keeps the drive-letter path, which relies on a standard user
// being unable to redefine an existing drive letter (the program's own
// drive here) in its own session. If Windows ever allows it, this fails.
func TestDriveLetterCantBeRedefined(t *testing.T) {
	skipIfElevated(t)
	dir := evalAbs(t, t.TempDir())
	letter := filepath.VolumeName(dir)
	if len(letter) != 2 || letter[1] != ':' {
		t.Skipf("the temporary folder %s is not on a drive letter", dir)
	}
	name, _ := windows.UTF16PtrFromString(letter)
	for _, c := range []struct {
		flags  uint32
		target string
	}{
		{0, dir},
		{windows.DDD_RAW_TARGET_PATH, `\??\` + dir},
	} {
		target, _ := windows.UTF16PtrFromString(c.target)
		err := windows.DefineDosDevice(c.flags, name, target)
		if err == nil {
			windows.DefineDosDevice(c.flags|windows.DDD_REMOVE_DEFINITION|windows.DDD_EXACT_MATCH_ON_REMOVE, name, target)
			t.Fatalf("a standard user redefined %s (flags %#x)", letter, c.flags)
		}
		t.Logf("redefining %s as a standard user (flags %#x): refused: %v", letter, c.flags, err)
	}
}

// The child has no console of the connector's: it runs with a console of
// its own (CREATE_NO_WINDOW), which this process is not attached to.
func TestStartGivesNoConsoleOfTheConnectors(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	out, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	spec := helperSpec(t, exe, "console")
	spec.Stdout = out
	proc, err := p.Start(spec)
	if err != nil {
		t.Fatal(err)
	}
	child := proc.Pid
	if code, err := proc.Wait(); err != nil || code != 0 {
		t.Fatalf("exit %d, %v", code, err)
	}
	b, _ := os.ReadFile(out.Name())
	pids := strings.Fields(string(b))
	for _, s := range pids {
		if s == strconv.Itoa(os.Getpid()) {
			t.Fatalf("the child shares this process's console: %v", pids)
		}
	}
	if len(pids) == 0 || pids[0] == "none" || !strings.Contains(" "+string(b), strconv.Itoa(child)) {
		t.Fatalf("the child's console holds %v; want the child's own", pids)
	}
}

// Only the standard handles are inherited: another inheritable handle of
// this process doesn't reach the child.
func TestStartInheritsOnlyTheStandardHandles(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	f, err := os.Create(filepath.Join(t.TempDir(), "vettid-inherit-probe"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := windows.Handle(f.Fd())
	if err := windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT); err != nil {
		t.Fatal(err)
	}
	code, out := runOutput(t, p, helperSpec(t, exe, "handle", Var{"VETTID_RUN_TEST_HANDLE", strconv.FormatUint(uint64(h), 10)}))
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(strings.ToLower(out), "vettid-inherit-probe") {
		t.Fatalf("the child holds the inheritable handle: %s", out)
	}
}

// A command line past CreateProcess's 32,767 characters once quoted is
// bad_request, and nothing starts.
func TestStartRefusesALongCommandLine(t *testing.T) {
	lookupOnly(t)
	exe := helperCopy(t, t.TempDir(), "helper")
	p := prepare(t, exe)
	marker := filepath.Join(t.TempDir(), "marker")
	spec := helperSpec(t, exe, "marker", Var{"VETTID_RUN_TEST_MARKER", marker})
	spec.Argv = []string{exe}
	for i := 0; i < 5; i++ {
		spec.Argv = append(spec.Argv, strings.Repeat(`"`, 4000)) // each quoted to 8,002
	}
	if _, err := p.Start(spec); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("long command line: %v, want bad_request", err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a process ran")
	}
}

// The environment block is sorted by name without case.
func TestEnvBlockSorted(t *testing.T) {
	b, err := envBlock([]string{"b=1", "A=2", "c=3", "B_=4"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range strings.Split(string(utf16.Decode(b)), "\x00") {
		if s != "" {
			got = append(got, s)
		}
	}
	if strings.Join(got, ",") != "A=2,b=1,B_=4,c=3" {
		t.Fatalf("block order %v", got)
	}
}
