//go:build windows

package run

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The access check is real, not vacuous: System32 grants this user read
// access (list the directory) but none of the rights that change it, and
// the user's own temporary directory grants those.
func TestAccessCheckIsReal(t *testing.T) {
	skipIfElevated(t)
	sys := filepath.Join(os.Getenv("SystemRoot"), "System32")
	sd, err := windows.GetNamedSecurityInfo(sys, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	g, err := maxAllowed(sd)
	if err != nil {
		t.Fatal(err)
	}
	const listDirectory = 0x0001
	if g&listDirectory == 0 {
		t.Fatalf("System32 grants %#x: no list right, so the check isn't working", g)
	}
	if g&dirRights != 0 {
		t.Fatalf("System32 grants %#x: a changing right (is the test running as an administrator?)", g)
	}
	if w, err := writable(t.TempDir(), false); err != nil || !w {
		t.Fatalf("own temporary directory: writable %v, %v", w, err)
	}
}

// The rights rule against fixed security descriptors, so it holds whatever
// the test's user may do (CI's runner is an administrator, which the
// on-disk tests skip). The owner is SYSTEM, so the test's user has no
// owner's rights; each case grants it, by its own SID, exactly the
// rights named.
func TestChangesRule(t *testing.T) {
	me := currentUserSID(t)
	read := "(A;;0x1200a9;;;WD)" // read and execute for everyone
	cases := []struct {
		name        string
		dacl        string
		own, parent bool // changes, as an own entry and as a folder above
	}{
		{"read only", read, false, false},
		{"add file only", read + "(A;;0x2;;;" + me + ")", true, false},
		{"add folder only", read + "(A;;0x4;;;" + me + ")", true, false},
		{"delete child", read + "(A;;0x40;;;" + me + ")", true, true},
		{"delete", read + "(A;;SD;;;" + me + ")", true, true},
		{"write access list", read + "(A;;WD;;;" + me + ")", true, true},
		{"write owner", read + "(A;;WO;;;" + me + ")", true, true},
		{"full", "(A;;FA;;;" + me + ")", true, true},
		{"denied", "(D;;FA;;;" + me + ")" + read, false, false},
		{"through a group (Users)", read + "(A;;0x2;;;BU)", true, false},
		{"inherit-only, not on this folder", read + "(A;OICIIO;FA;;;" + me + ")", false, false},
	}
	for _, c := range cases {
		sd, err := windows.SecurityDescriptorFromString("O:SYG:SYD:P" + c.dacl)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		for _, parent := range []bool{false, true} {
			got, err := changes(sd, parent)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			want := c.own
			if parent {
				want = c.parent
			}
			if got != want {
				t.Errorf("%s, parent %v: changes %v, want %v", c.name, parent, got, want)
			}
		}
	}
	// The owner may change the access list, whatever the list says.
	sd, err := windows.SecurityDescriptorFromString("O:" + me + "G:SYD:P" + read)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := changes(sd, true); err != nil || !got {
		t.Errorf("owned by the user: changes %v, %v", got, err)
	}
}

func currentUserSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// SystemRoot, windir, SystemDrive and PATHEXT come from the system, not
// from the connector's environment, whatever its starter set.
func TestEnvWindowsSystemVars(t *testing.T) {
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	decoy := map[string]string{"SystemRoot": `C:\decoy`, "windir": `C:\decoy`, "SystemDrive": "Z:", "PATHEXT": ".BAT;.CMD;.EXE"}
	env, err := Env(Spec{Tmp: t.TempDir()}, mapLookup(decoy))
	if err != nil {
		t.Fatal(err)
	}
	got := envMap(t, env)
	want := map[string]string{"SystemRoot": filepath.Clean(root), "windir": filepath.Clean(root),
		"SystemDrive": filepath.VolumeName(root), "PATHEXT": ".COM;.EXE"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// A drive letter mapped to a folder (subst) is refused: its user can point
// it elsewhere after the check.
func TestSubstDriveRefused(t *testing.T) {
	dir := t.TempDir()
	letter := ""
	for c := 'Z'; c >= 'M'; c-- {
		if _, err := os.Stat(string(c) + `:\`); err != nil {
			letter = string(c) + ":"
			break
		}
	}
	if letter == "" {
		t.Skip("no free drive letter")
	}
	if out, err := exec.Command("subst", letter, dir).CombinedOutput(); err != nil {
		t.Fatalf("subst: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("subst", letter, "/d").Run() })
	_, err := CheckRunPaths([]string{letter + `\`})
	if err == nil || !strings.Contains(err.Error(), "subst") {
		t.Fatalf("subst drive: %v", err)
	}
}

// A drive letter defined with a raw target that names a folder on a disk
// device acts as subst does, and is refused the same way.
func TestRawTargetDriveRefused(t *testing.T) {
	dir := t.TempDir()
	vol := filepath.VolumeName(dir)
	vp, _ := windows.UTF16PtrFromString(vol)
	buf := make([]uint16, 1024)
	n, err := windows.QueryDosDevice(vp, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatal(err)
	}
	device := windows.UTF16ToString(buf[:n])
	letter := ""
	for c := 'Z'; c >= 'M'; c-- {
		if _, err := os.Stat(string(c) + ":" + string(os.PathSeparator)); err != nil {
			letter = string(c) + ":"
			break
		}
	}
	if letter == "" {
		t.Skip("no free drive letter")
	}
	lp, _ := windows.UTF16PtrFromString(letter)
	tp, _ := windows.UTF16PtrFromString(device + dir[len(vol):])
	if err := windows.DefineDosDevice(windows.DDD_RAW_TARGET_PATH, lp, tp); err != nil {
		t.Fatalf("DefineDosDevice: %v", err)
	}
	t.Cleanup(func() {
		windows.DefineDosDevice(windows.DDD_RAW_TARGET_PATH|windows.DDD_REMOVE_DEFINITION|windows.DDD_EXACT_MATCH_ON_REMOVE, lp, tp)
	})
	_, err = CheckRunPaths([]string{letter + string(os.PathSeparator)})
	if err == nil || !strings.Contains(err.Error(), "subst") {
		t.Fatalf("raw-target drive: %v", err)
	}
}

// A junction to a protected directory is refused: it's resolved by
// nothing before the check, and its owner could repoint it later.
// (Junctions need no privilege, so making one failing is a test failure.)
func TestJunctionRunPathRefused(t *testing.T) {
	link := filepath.Join(t.TempDir(), "j")
	target := os.Getenv("SystemRoot")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("can't make a junction: %v %s", err, out)
	}
	// At the leaf: the check names it.
	if _, err := CheckRunPaths([]string{link}); err == nil || !strings.Contains(err.Error(), "junction") {
		t.Errorf("junction at the leaf: %v", err)
	}
	// Under a junction (it as a parent): refused too, already when links
	// are resolved, which fails on a path through a junction.
	if _, err := CheckRunPaths([]string{filepath.Join(link, "System32")}); err == nil {
		t.Error("a path under a junction accepted")
	}
}

// A program extension after a stream name doesn't make a program.
// The stream exists, so it's the ":" rule that refuses it.
func TestStreamNameIsNotAProgram(t *testing.T) {
	file := filepath.Join(t.TempDir(), "x.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream := file + ":s.exe"
	if err := os.WriteFile(stream, []byte("MZ"), 0o600); err != nil {
		t.Fatalf("can't write a stream: %v", err)
	}
	if _, err := os.Stat(stream); err != nil {
		t.Fatalf("stream not there: %v", err)
	}
	if _, err := Resolve(stream, nil); err == nil {
		t.Fatal("x.txt:s.exe accepted")
	}
}

// skipIfElevated: as an administrator, every folder can be changed, so a
// test of a protected folder can't hold (and the connector refuses all
// programs, which fails closed).
func skipIfElevated(t *testing.T) {
	t.Helper()
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("running as an administrator: every folder can be changed")
	}
}
