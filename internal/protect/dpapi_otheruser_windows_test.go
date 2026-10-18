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
	"time"
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

// addTestUser creates a local user, registers its deletion (profile
// first, then the account; a failure is a test error) and returns its
// SID.
func addTestUser(t *testing.T, name, password string) string {
	t.Helper()
	addLocalUser(t, name, password)
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		deleteLocalUser(t, name)
		t.Fatalf("LookupSID %s: %v", name, err)
	}
	s := sid.String()
	t.Cleanup(func() {
		deleteProfile(t, s)
		deleteLocalUser(t, name)
	})
	return s
}

// deleteProfile deletes a user's profile, retrying while Windows still
// has it loaded; a profile that was never created is not an error.
func deleteProfile(t *testing.T, sid string) {
	t.Helper()
	p, _ := windows.UTF16PtrFromString(sid)
	var errno windows.Errno
	for i := 0; i < 15; i++ {
		r, _, e := procDeleteProfileW.Call(uintptr(unsafe.Pointer(p)), 0, 0)
		if r != 0 {
			return
		}
		errno, _ = e.(windows.Errno)
		if errno == windows.ERROR_FILE_NOT_FOUND || errno == windows.ERROR_PATH_NOT_FOUND {
			return
		}
		time.Sleep(time.Second)
	}
	t.Errorf("the profile of %s was not deleted: %v", sid, errno)
}

func deleteLocalUser(t *testing.T, name string) {
	t.Helper()
	n, _ := windows.UTF16PtrFromString(name)
	if r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(n))); r != 0 {
		t.Errorf("NetUserDel %s: %v", name, windows.Errno(r))
	}
}

// createRestrictedDir creates a new directory under the system drive's
// root whose protected DACL, set at creation (so there is no moment when
// other users could add entries), gives full access to Administrators
// and the given SIDs only, inherited by what is created in it.
func createRestrictedDir(t *testing.T, sids ...string) string {
	t.Helper()
	sddl := "D:P(A;OICI;FA;;;BA)"
	for _, s := range sids {
		sddl += "(A;OICI;FA;;;" + s + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for i := 0; i < 10; i++ {
		dir := os.Getenv("SystemDrive") + `\vettid-agent-dpapi-` + randHex(t, 8)
		p, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			t.Fatal(err)
		}
		err = windows.CreateDirectory(p, sa)
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			continue
		}
		if err != nil {
			t.Fatalf("create the test directory: %v", err)
		}
		return dir
	}
	t.Fatal("could not create a test directory with a new name")
	return ""
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
	case "choose":
		c, err := ChooseProtector(ChooseOptions{})
		if err != nil {
			result("error\n" + kindOf(err) + "\n" + err.Error())
			return
		}
		result("ok\n" + c.Protector + "\n")
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
	// The secondary logon service runs CreateProcessWithLogonW.
	exec.Command("sc.exe", "config", "seclogon", "start=", "demand").Run()
	exec.Command("sc.exe", "start", "seclogon").Run()

	// Two test users: the other user, and one started without its
	// profile (step 4). Each is deleted with its profile afterwards; a
	// failure to delete fails the test.
	user := "vta" + randHex(t, 4)
	pass := "Va1!" + randHex(t, 12) + "-x"
	sid1 := addTestUser(t, user, pass)
	user2 := "vtb" + randHex(t, 4)
	pass3 := "Vc3!" + randHex(t, 12) + "-z"
	sid2 := addTestUser(t, user2, pass3)

	// A directory only the test users and Administrators can use: the
	// helper binary, the blobs and the results.
	dir := createRestrictedDir(t, sid1, sid2)
	t.Cleanup(func() {
		var err error
		for i := 0; i < 10; i++ {
			if err = os.RemoveAll(dir); err == nil {
				return
			}
			time.Sleep(time.Second)
		}
		t.Errorf("the test directory %s was not removed: %v", dir, err)
	})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "helper.exe")
	copyFile(t, self, helper)

	helperRunAs := func(user, password string, logonFlags uintptr, op, blob string) (status, kind, msg string) {
		t.Helper()
		res := filepath.Join(dir, "result-"+randHex(t, 4))
		code := runAsUser(t, user, password, logonFlags, dir, helper,
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
	helperRun := func(password, op, blob string) (string, string, string) {
		t.Helper()
		return helperRunAs(user, password, logonWithProfile, op, blob)
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
	// Windows answers NTE_BAD_KEY_STATE: the blob's master key is not
	// in the other user's profile.
	if status != "error" || kind != "keylost" || !strings.Contains(msg, "another Windows user") {
		t.Errorf("other user opening this user's key: %s %s: %s; want ErrDPAPIKeyLost naming another user", status, kind, msg)
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
	if !errors.Is(err, ErrDPAPIKeyLost) || !strings.Contains(err.Error(), "another Windows user") {
		t.Errorf("this user opening the other user's key: %v; want ErrDPAPIKeyLost naming another user", err)
	}

	// 3. An administrator resets the other user's password: the user's
	// earlier key no longer opens (ErrDPAPIKeyLost naming the reset).
	pass2 := "Vb2!" + randHex(t, 12) + "-y"
	resetPassword(t, user, pass2)
	status, kind, msg = helperRun(pass2, "unwrap", theirsPath)
	t.Logf("other user opening its key after an administrator reset its password: %s %s: %s", status, kind, msg)
	// NTE_BAD_KEY_STATE again, but the master key file is present.
	if status != "error" || kind != "keylost" || !strings.Contains(msg, "administrator reset") {
		t.Errorf("after a password reset: %s %s: %s; want ErrDPAPIKeyLost naming the reset", status, kind, msg)
	}
	// 4. A user whose profile is not loaded (a new user, started without
	// loading its profile): DPAPI cannot reach the user's keys, an
	// environmental error, not a definite one.
	status, kind, msg = helperRunAs(user2, pass3, logonNoProfile, "wrap", filepath.Join(dir, "noprofile.blob"))
	t.Logf("a user without a loaded profile wrapping a key: %s %s: %s", status, kind, msg)
	if status != "error" || kind != "profile" {
		t.Errorf("without a loaded profile: %s %s: %s; want ErrDPAPIProfile", status, kind, msg)
	}
	// ChooseProtector there: an error with the cause, not a silent
	// passphrase.
	status, kind, msg = helperRunAs(user2, pass3, logonNoProfile, "choose", "-")
	t.Logf("ChooseProtector without a loaded profile: %s %s: %s", status, kind, msg)
	if status != "error" || kind != "profile" || !strings.Contains(msg, "choose a passphrase") {
		t.Errorf("ChooseProtector without a loaded profile: %s %s: %s; want ErrDPAPIProfile", status, kind, msg)
	}
	// With the profile loaded, the same user gets DPAPI.
	if status, kind, msg := helperRunAs(user2, pass3, logonWithProfile, "choose", "-"); status != "ok" || kind != DPAPIName {
		t.Errorf("ChooseProtector with the profile loaded: %s %s: %s", status, kind, msg)
	}

	// And new keys work again for that user.
	newPath := filepath.Join(dir, "new.blob")
	if status, kind, msg := helperRun(pass2, "wrap", newPath); status != "ok" {
		t.Errorf("other user wrap after the reset: %s %s: %s", status, kind, msg)
	} else if status, kind, msg := helperRun(pass2, "unwrap", newPath); status != "ok" {
		t.Errorf("other user unwrap after the reset: %s %s: %s", status, kind, msg)
	}
}

// CreateProcessWithLogonW's logon flags: 0 does not load the profile.
const (
	logonWithProfile = 1
	logonNoProfile   = 0
)

// runAsUser starts app with args as user (a local account) with the
// user's profile loaded, waits for it, and returns its exit code.
func runAsUser(t *testing.T, user, password string, logonFlags uintptr, cwd, app string, args ...string) uint32 {
	t.Helper()
	u, _ := windows.UTF16PtrFromString(user)
	d, _ := windows.UTF16PtrFromString(".")
	p, _ := windows.UTF16PtrFromString(password)
	a, _ := windows.UTF16PtrFromString(app)
	c, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{app}, args...)))
	w, _ := windows.UTF16PtrFromString(cwd)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Flags: windows.STARTF_USESHOWWINDOW, ShowWindow: windows.SW_HIDE}
	var pi windows.ProcessInformation
	r, _, e := procCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(p)),
		logonFlags, uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(c)),
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
