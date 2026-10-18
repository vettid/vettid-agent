//go:build windows

package protect

// "Another Windows user cannot open the key" (AGENT-PLAN §6 A1.4), as an
// automated test. It creates a local user, runs this test binary as that
// user (CreateProcessWithLogonW with the user's profile loaded) in
// helper mode, and checks both directions: a key wrapped here does not
// open for the other user, and a key the other user wrapped does not
// open here, while it does open for that user (so the helper is shown
// to work). It then resets the other user's password as an
// administrator and checks that the user's earlier key no longer opens
// (DPAPI's master keys are lost on an administrator reset).
//
// It runs only with VETTID_AGENT_TEST_OTHER_USER=1 (set by the Windows
// CI job, which runs as an administrator) and fails, rather than skips,
// if that is set and the process is not elevated. It never runs on a
// developer's computer by accident.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const otherUserEnv = "VETTID_AGENT_TEST_OTHER_USER"

var (
	modAdvapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	procCreateProcessWithLogonW = modAdvapi32.NewProc("CreateProcessWithLogonW")
	modUserenv                  = windows.NewLazySystemDLL("userenv.dll")
	procDeleteProfileW          = modUserenv.NewProc("DeleteProfileW")
	modNetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = modNetapi32.NewProc("NetUserAdd")
	procNetUserSetInfo          = modNetapi32.NewProc("NetUserSetInfo")
	procNetUserDel              = modNetapi32.NewProc("NetUserDel")
)

// userInfo1 is USER_INFO_1.
type userInfo1 struct {
	name, password *uint16
	passwordAge    uint32
	priv           uint32
	homeDir        *uint16
	comment        *uint16
	flags          uint32
	scriptPath     *uint16
}

// addLocalUser creates a local user (NetUserAdd, level 1).
func addLocalUser(t *testing.T, name, password string) {
	t.Helper()
	n, _ := windows.UTF16PtrFromString(name)
	p, _ := windows.UTF16PtrFromString(password)
	const userPrivUser, ufScript, ufDontExpirePasswd = 1, 0x1, 0x10000
	ui := userInfo1{name: n, password: p, priv: userPrivUser, flags: ufScript | ufDontExpirePasswd}
	var parmErr uint32
	if r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&ui)), uintptr(unsafe.Pointer(&parmErr))); r != 0 {
		t.Fatalf("NetUserAdd: %v (parameter %d)", windows.Errno(r), parmErr)
	}
}

// resetPassword sets a user's password as an administrator
// (NetUserSetInfo, level 1003), without the old password.
func resetPassword(t *testing.T, name, password string) {
	t.Helper()
	n, _ := windows.UTF16PtrFromString(name)
	p, _ := windows.UTF16PtrFromString(password)
	ui := struct{ password *uint16 }{p}
	var parmErr uint32
	if r, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(n)), 1003, uintptr(unsafe.Pointer(&ui)), uintptr(unsafe.Pointer(&parmErr))); r != 0 {
		t.Fatalf("NetUserSetInfo: %v", windows.Errno(r))
	}
}

func deleteLocalUser(name string) {
	n, _ := windows.UTF16PtrFromString(name)
	procNetUserDel.Call(0, uintptr(unsafe.Pointer(n)))
}

// TestDPAPIHelper is the helper mode: it runs only when the test binary
// is started with the arguments `dpapi-helper wrap|unwrap BLOB RESULT`.
func TestDPAPIHelper(t *testing.T) {
	args := flag.Args()
	if len(args) != 4 || args[0] != "dpapi-helper" {
		t.Skip("helper mode only")
	}
	op, blobPath, resultPath := args[1], args[2], args[3]
	result := func(s string) {
		if err := os.WriteFile(resultPath, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := NewDPAPI()
	switch op {
	case "wrap":
		blob, err := p.Wrap(testKey(0x77))
		if err != nil {
			result("error\n" + kindOf(err) + "\n" + err.Error())
			return
		}
		if err := os.WriteFile(blobPath, blob, 0o600); err != nil {
			t.Fatal(err)
		}
		result("ok\n")
	case "unwrap":
		blob, err := os.ReadFile(blobPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Unwrap(blob); err != nil {
			result("error\n" + kindOf(err) + "\n" + err.Error())
			return
		}
		result("ok\n")
	default:
		t.Fatalf("unknown op %q", op)
	}
}

func kindOf(err error) string {
	switch {
	case errors.Is(err, ErrDPAPIBlobFormat):
		return "format"
	case errors.Is(err, ErrDPAPIRefused):
		return "refused"
	case errors.Is(err, ErrDPAPIKeyLost):
		return "keylost"
	case errors.Is(err, ErrDPAPIProfile):
		return "profile"
	default:
		return "other"
	}
}

func TestDPAPIOtherUser(t *testing.T) {
	if os.Getenv(otherUserEnv) != "1" {
		t.Skipf("set %s=1 to create a local user and test with it (CI only)", otherUserEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%s=1 needs an elevated (administrator) process", otherUserEnv)
	}
	run := func(name string, args ...string) {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %s: %v: %s", name, args[0], err, out)
		}
	}
	// The secondary logon service runs CreateProcessWithLogonW.
	exec.Command("sc.exe", "config", "seclogon", "start=", "demand").Run()
	exec.Command("sc.exe", "start", "seclogon").Run()

	// A directory the other user can read and write: the helper binary,
	// the blobs and the results.
	dir, err := os.MkdirTemp(os.Getenv("SystemDrive")+`\`, "vettid-agent-dpapi-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	run("icacls.exe", dir, "/grant", "*S-1-5-11:(OI)(CI)M") // Authenticated Users
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "helper.exe")
	copyFile(t, self, helper)

	user := "vta" + randHex(t, 4)
	pass := "Va1!" + randHex(t, 12) + "-x"
	addLocalUser(t, user, pass)
	t.Cleanup(func() {
		if sid, _, _, err := windows.LookupSID("", user); err == nil {
			if s, err := windows.UTF16PtrFromString(sid.String()); err == nil {
				procDeleteProfileW.Call(uintptr(unsafe.Pointer(s)), 0, 0)
			}
		}
		deleteLocalUser(user)
	})

	helperRun := func(password, op, blob string) (status, kind, msg string) {
		t.Helper()
		res := filepath.Join(dir, "result-"+randHex(t, 4))
		code := runAsUser(t, user, password, dir, helper,
			"-test.run=^TestDPAPIHelper$", "-test.count=1", "-test.timeout=2m",
			"dpapi-helper", op, blob, res)
		b, err := os.ReadFile(res)
		if err != nil {
			t.Fatalf("helper %s as %s: exit code %d, no result: %v", op, user, code, err)
		}
		parts := strings.SplitN(string(b), "\n", 3)
		for len(parts) < 3 {
			parts = append(parts, "")
		}
		return parts[0], parts[1], parts[2]
	}

	// 1. A key wrapped by this user does not open for the other user.
	mine, err := NewDPAPI().Wrap(testKey(0x11))
	if err != nil {
		t.Fatal(err)
	}
	minePath := filepath.Join(dir, "mine.blob")
	if err := os.WriteFile(minePath, mine, 0o644); err != nil {
		t.Fatal(err)
	}
	status, kind, msg := helperRun(pass, "unwrap", minePath)
	t.Logf("other user opening this user's key: %s %s: %s", status, kind, msg)
	if status != "error" || (kind != "refused" && kind != "keylost") {
		t.Errorf("other user opening this user's key: %s %s: %s; want a definite refusal", status, kind, msg)
	}

	// 2. The other user's key opens for that user and not here.
	theirsPath := filepath.Join(dir, "theirs.blob")
	if status, kind, msg := helperRun(pass, "wrap", theirsPath); status != "ok" {
		t.Fatalf("other user wrap: %s %s: %s", status, kind, msg)
	}
	if status, kind, msg := helperRun(pass, "unwrap", theirsPath); status != "ok" {
		t.Fatalf("other user opening its own key: %s %s: %s", status, kind, msg)
	}
	theirs, err := os.ReadFile(theirsPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewDPAPI().Unwrap(theirs)
	t.Logf("this user opening the other user's key: %v", err)
	if k := kindOf(err); err == nil || (k != "refused" && k != "keylost") {
		t.Errorf("this user opening the other user's key: %v; want a definite refusal", err)
	}

	// 3. An administrator resets the other user's password: the user's
	// earlier key no longer opens, as a definite error.
	pass2 := "Vb2!" + randHex(t, 12) + "-y"
	resetPassword(t, user, pass2)
	status, kind, msg = helperRun(pass2, "unwrap", theirsPath)
	t.Logf("other user opening its key after an administrator reset its password: %s %s: %s", status, kind, msg)
	if status != "error" || (kind != "keylost" && kind != "refused") {
		t.Errorf("after a password reset: %s %s: %s; want a definite error", status, kind, msg)
	}
	// And new keys work again for that user.
	newPath := filepath.Join(dir, "new.blob")
	if status, kind, msg := helperRun(pass2, "wrap", newPath); status != "ok" {
		t.Errorf("other user wrap after the reset: %s %s: %s", status, kind, msg)
	} else if status, kind, msg := helperRun(pass2, "unwrap", newPath); status != "ok" {
		t.Errorf("other user unwrap after the reset: %s %s: %s", status, kind, msg)
	}
}

// runAsUser starts app with args as user (a local account) with the
// user's profile loaded, waits for it, and returns its exit code.
func runAsUser(t *testing.T, user, password, cwd, app string, args ...string) uint32 {
	t.Helper()
	u, _ := windows.UTF16PtrFromString(user)
	d, _ := windows.UTF16PtrFromString(".")
	p, _ := windows.UTF16PtrFromString(password)
	a, _ := windows.UTF16PtrFromString(app)
	c, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{app}, args...)))
	w, _ := windows.UTF16PtrFromString(cwd)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	var pi windows.ProcessInformation
	const logonWithProfile = 1
	r, _, e := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)),
		logonWithProfile, uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(c)),
		windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT, 0, uintptr(unsafe.Pointer(w)),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		t.Fatalf("CreateProcessWithLogonW: %v", e)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	ev, err := windows.WaitForSingleObject(pi.Process, 180_000)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		windows.TerminateProcess(pi.Process, 1)
		t.Fatalf("helper did not finish: %v %v", ev, err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		t.Fatal(err)
	}
	return code
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(to)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
