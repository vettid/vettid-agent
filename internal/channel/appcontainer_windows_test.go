//go:build windows

package channel

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	moduserenv                        = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile     = moduserenv.NewProc("CreateAppContainerProfile")
	procDeriveAppContainerSidFromName = moduserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	procDeleteAppContainerProfile     = moduserenv.NewProc("DeleteAppContainerProfile")
)

const procThreadAttributeSecurityCapabilities = 0x00020009

type securityCapabilities struct {
	appContainerSid *windows.SID
	capabilities    *windows.SIDAndAttributes
	capabilityCount uint32
	reserved        uint32
}

// Exit codes of the AppContainer client.
const (
	acDialed     = 0
	acNotAllowed = 3
	acOther      = 4
	acDenied     = 5 // refused by the access list at open
)

// TestAppContainerClientHelper is the client run inside an AppContainer
// by TestAppContainerRefused; on its own it does nothing.
func TestAppContainerClientHelper(t *testing.T) {
	pipe := os.Getenv("VETTID_TEST_AC_PIPE")
	if pipe == "" {
		t.Skip("run by TestAppContainerRefused")
	}
	f, err := Dial(context.Background(), DialConfig{Pipe: pipe, Service: os.Getenv("VETTID_TEST_AC_OWNER"), Op: OpMCP, Version: testVersion})
	switch {
	case err == nil:
		f.Close()
		os.Exit(acDialed)
	case errors.Is(err, ErrAccessDenied):
		os.Exit(acDenied)
	case errors.Is(err, ErrNotAllowed):
		os.Exit(acNotAllowed)
	default:
		os.Exit(acOther)
	}
}

// An AppContainer client is refused: by the access list (it has no
// entry for app packages), and by the server even when one is added.
func TestAppContainerRefused(t *testing.T) {
	name := "vettid-agent-channel-test"
	n, _ := windows.UTF16PtrFromString(name)
	var sid *windows.SID
	hr, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if hr == 0x800700B7 { // already exists
		hr, _, _ = procDeriveAppContainerSidFromName.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid)))
	}
	if hr != 0 {
		t.Fatalf("AppContainer profile: %#x", hr)
	}
	t.Cleanup(func() {
		windows.FreeSid(sid)
		procDeleteAppContainerProfile.Call(uintptr(unsafe.Pointer(n)))
	})
	// The test binary must be readable and runnable from the container.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls", exe, "/grant", "*"+sid.String()+":(RX)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	me := selfSID(t)
	for _, c := range []struct {
		name, extra     string
		refusedByServer bool
	}{
		{"access list", "", false},
		{"server", "(A;;0x120083;;;AC)", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := listen(t, me, c.extra)
			t.Setenv("VETTID_TEST_AC_PIPE", s.pipe)
			t.Setenv("VETTID_TEST_AC_OWNER", me)
			code := runInAppContainer(t, sid, exe, "-test.run=^TestAppContainerClientHelper$")
			want := uint32(acDenied)
			if c.refusedByServer {
				want = acNotAllowed
			}
			if code != want {
				t.Fatalf("the AppContainer client exited %#x, want %d", code, want)
			}
			if c.refusedByServer {
				got := s.refused.wait(t, 1)
				if !strings.Contains(got[0].Error(), "AppContainer") {
					t.Fatalf("server refused it with %v", got[0])
				}
			}
			select {
			case sc := <-s.conns:
				sc.Close()
				t.Fatal("the server admitted an AppContainer client")
			default:
			}
		})
	}
}

// runInAppContainer runs exe with args in the AppContainer of sid, with
// no capabilities, and returns its exit code.
func runInAppContainer(t *testing.T, sid *windows.SID, exe string, args ...string) uint32 {
	t.Helper()
	al, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Delete()
	sc := securityCapabilities{appContainerSid: sid}
	if err := al.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&sc), unsafe.Sizeof(sc)); err != nil {
		t.Fatal(err)
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: al.List()}
	si.Cb = uint32(unsafe.Sizeof(*si))
	cmd := syscall.EscapeArg(exe)
	for _, a := range args {
		cmd += " " + syscall.EscapeArg(a)
	}
	cl, _ := windows.UTF16PtrFromString(cmd)
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, cl, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_NO_WINDOW,
		nil, nil, &si.StartupInfo, &pi); err != nil {
		t.Fatalf("CreateProcess in an AppContainer: %v", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	if ev, err := windows.WaitForSingleObject(pi.Process, uint32((30 * time.Second).Milliseconds())); err != nil || ev != windows.WAIT_OBJECT_0 {
		windows.TerminateProcess(pi.Process, 1)
		t.Fatalf("the AppContainer client did not end: %v", err)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		t.Fatal(err)
	}
	return code
}
