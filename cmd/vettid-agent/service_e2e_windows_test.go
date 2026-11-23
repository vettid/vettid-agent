//go:build windows

package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/mcp"
)

// serviceBinaryEnv names the vettid-agent binary the end-to-end test
// installs as a service; the CI step builds it.
const serviceBinaryEnv = "VETTID_AGENT_TEST_SERVICE_BINARY"

var (
	modnetapi32e2e              = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAddE2E           = modnetapi32e2e.NewProc("NetUserAdd")
	procNetUserDelE2E           = modnetapi32e2e.NewProc("NetUserDel")
	procNetLocalGroupAddMembers = modnetapi32e2e.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMembers = modnetapi32e2e.NewProc("NetLocalGroupDelMembers")
	procLogonUserE2E            = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
	procImpersonateE2E          = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")
	procDeleteProfileE2E        = windows.NewLazySystemDLL("userenv.dll").NewProc("DeleteProfileW")
)

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// e2eUser is a throwaway standard local user, logged on (interactive
// logon, no profile loaded); removed when the test ends.
type e2eUser struct {
	name  string
	sid   *windows.SID
	token windows.Token
}

func newE2EUser(t *testing.T) *e2eUser {
	t.Helper()
	name := "vtest" + randomHex(4)
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	pass := base64.RawURLEncoding.EncodeToString(pw) + "Aa1!"
	n, _ := windows.UTF16PtrFromString(name)
	p, _ := windows.UTF16PtrFromString(pass)
	info := struct {
		name, password *uint16
		passwordAge    uint32
		priv           uint32
		homeDir        *uint16
		comment        *uint16
		flags          uint32
		scriptPath     *uint16
	}{name: n, password: p, priv: 1, flags: 0x1 | 0x10000}
	var parm uint32
	if r, _, _ := procNetUserAddE2E.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm))); r != 0 {
		t.Fatalf("NetUserAdd: %d (parameter %d)", r, parm)
	}
	u := &e2eUser{name: name}
	t.Cleanup(func() {
		if u.token != 0 {
			u.token.Close()
		}
		if r, _, _ := procNetUserDelE2E.Call(0, uintptr(unsafe.Pointer(n))); r != 0 {
			t.Errorf("NetUserDel %s: %d", name, r)
		}
		if u.sid != nil {
			sp, _ := windows.UTF16PtrFromString(u.sid.String())
			_, _, _ = procDeleteProfileE2E.Call(uintptr(unsafe.Pointer(sp)), 0, 0)
		}
	})
	dot, _ := windows.UTF16PtrFromString(".")
	if r, _, e := procLogonUserE2E.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(p)),
		2 /* LOGON32_LOGON_INTERACTIVE */, 0, uintptr(unsafe.Pointer(&u.token))); r == 0 {
		t.Fatalf("LogonUser: %v", e)
	}
	tu, err := u.token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if u.sid, err = tu.User.Sid.Copy(); err != nil {
		t.Fatal(err)
	}
	return u
}

// as runs f on a thread impersonating u.
func (u *e2eUser) as(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		if r, _, e := procImpersonateE2E.Call(uintptr(u.token)); r == 0 {
			runtime.UnlockOSThread()
			t.Errorf("ImpersonateLoggedOnUser: %v", e)
			return
		}
		defer func() {
			if windows.RevertToSelf() == nil {
				runtime.UnlockOSThread()
			}
		}()
		f()
	}()
	<-done
}

// runAs runs vettid-agent's command line in this process as u (or as
// this process, the elevated administrator, if u is nil).
func runAs(t *testing.T, u *e2eUser, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	rc := 0
	f := func() { rc = run(args, &out, &errOut) }
	if u == nil {
		f()
	} else {
		u.as(t, f)
	}
	return rc, out.String(), errOut.String()
}

func setSecurity(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	dacl, _, _ := sd.DACL()
	si := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if owner != nil {
		si |= windows.OWNER_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, si, owner, nil, dacl, nil); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// installed is one pairing's connector service as the test installs it,
// the way the installer will (A5.5).
type installed struct {
	n, name, sid string
	member       *e2eUser
	svc          *mgr.Service
	stateDir     string
}

func (in *installed) query(t *testing.T) windows.SERVICE_STATUS_PROCESS {
	t.Helper()
	var ss windows.SERVICE_STATUS_PROCESS
	var need uint32
	if err := windows.QueryServiceStatusEx(in.svc.Handle, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&ss)), uint32(unsafe.Sizeof(ss)), &need); err != nil {
		t.Fatal(err)
	}
	return ss
}

func (in *installed) waitState(t *testing.T, state uint32, within time.Duration) windows.SERVICE_STATUS_PROCESS {
	t.Helper()
	for end := time.Now().Add(within); ; time.Sleep(200 * time.Millisecond) {
		ss := in.query(t)
		if ss.CurrentState == state {
			return ss
		}
		if time.Now().After(end) {
			t.Fatalf("the service is in state %d after %v, want %d (exit %d, service exit %d)",
				ss.CurrentState, within, state, ss.Win32ExitCode, ss.ServiceSpecificExitCode)
		}
	}
}

func (in *installed) stop(t *testing.T) {
	t.Helper()
	if ss := in.query(t); ss.CurrentState == windows.SERVICE_STOPPED {
		return
	}
	if _, err := in.svc.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		t.Fatalf("stop: %v", err)
	}
	in.waitState(t, windows.SERVICE_STOPPED, 30*time.Second)
}

func install(t *testing.T, m *mgr.Mgr) *installed {
	t.Helper()
	bin := os.Getenv(serviceBinaryEnv)
	if bin == "" {
		t.Fatalf("%s names the vettid-agent binary to install", serviceBinaryEnv)
	}
	in := &installed{n: "e2e" + randomHex(4)}
	in.name = channel.ServiceName(in.n)
	in.sid = channel.ServiceSID(in.name)
	in.member = newE2EUser(t)

	// The program, in an administrator-only folder.
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(pf, "VettID-test-"+in.n)
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(binDir) })
	exe := filepath.Join(binDir, "vettid-agent.exe")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}

	// The configuration: the pipe's name, the member, a short idle stop.
	pipe := "vettid-agent-" + in.n + "-" + randomHex(16)
	cfg, err := channel.ConfigPath(in.n)
	if err != nil {
		t.Fatal(err)
	}
	agentDir := filepath.Dir(cfg)
	if _, err := os.Stat(agentDir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(agentDir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(agentDir); os.Remove(filepath.Dir(agentDir)) })
	}
	// The agent folder: administrators and SYSTEM change it, Users read
	// it, and the service's account may also make its state folder in it.
	setSecurity(t, agentDir, "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;;0x1200ad;;;"+in.sid+")")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`{"pipe":%q,"member":%q,"idle_stop_seconds":10}`, pipe, in.member.sid.String())), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(cfg) })
	setSecurity(t, cfg, "O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)")
	in.stateDir = filepath.Join(agentDir, in.n)
	t.Cleanup(func() {
		// The state folder is the service's own; an administrator takes it
		// to remove it.
		if _, err := os.Stat(in.stateDir); err == nil || !errors.Is(err, os.ErrNotExist) {
			_ = exec.Command("takeown", "/f", in.stateDir, "/r", "/d", "y").Run()
			_ = exec.Command("icacls", in.stateDir, "/reset", "/t").Run()
			if err := os.RemoveAll(in.stateDir); err != nil {
				t.Errorf("removing %s: %v", in.stateDir, err)
			}
		}
	})

	if err := eventlog.InstallAsEventCreate(in.name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		t.Fatalf("the event source: %v", err)
	}
	t.Cleanup(func() { _ = eventlog.Remove(in.name) })

	s, err := m.CreateService(in.name, exe, mgr.Config{
		DisplayName:      in.name,
		StartType:        mgr.StartManual,
		ServiceStartName: `NT SERVICE\` + in.name,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "service", "--name", in.n)
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	in.svc = s
	t.Cleanup(func() {
		in.stop(t)
		if err := s.Delete(); err != nil {
			t.Errorf("deleting %s: %v", in.name, err)
		}
		s.Close()
		sp, _ := windows.UTF16PtrFromString(in.sid)
		_, _, _ = procDeleteProfileE2E.Call(uintptr(unsafe.Pointer(sp)), 0, 0)
	})
	privs := utf16.Encode([]rune("SeChangeNotifyPrivilege\x00\x00"))
	rp := struct{ privileges *uint16 }{&privs[0]}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&rp))); err != nil {
		t.Fatalf("required privileges: %v", err)
	}
	// Crash restart, at most three times a minute; a refusal of its own
	// (a code) is not a crash and is not restarted.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Second},
	}, 60); err != nil {
		t.Fatalf("recovery actions: %v", err)
	}
	// The service's own access list: Windows' default, plus the member,
	// who may start it and query it (on-demand start).
	sd, err := windows.SecurityDescriptorFromString("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;LCRPRC;;;" + in.member.sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("the service's access list: %v", err)
	}
	return in
}

// The connector as a real service per pairing, end to end (AGENT-PLAN
// A3.10b's Windows tests, the parts that need no vault): started on
// demand by the member, the account's self-check, the state folder and
// the process out of the member's reach, other users refused, the idle
// stop, crash restart, and a squatted channel name or an account in
// Administrators refusing to start, with status saying why. CI only.
func TestServiceEndToEnd(t *testing.T) {
	requireElevated(t)
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	in := install(t, m)
	other := newE2EUser(t)

	t.Run("another user can't start it", func(t *testing.T) {
		rc, _, errOut := runAs(t, other, "status", "--name", in.n)
		if rc != 1 || !strings.Contains(errOut, "Access is denied") {
			t.Fatalf("exit %d, stderr %q", rc, errOut)
		}
		if ss := in.query(t); ss.CurrentState != windows.SERVICE_STOPPED {
			t.Fatalf("state %d", ss.CurrentState)
		}
		t.Logf("another user: %s", errOut)
	})

	var pid uint32
	t.Run("started on demand by the member", func(t *testing.T) {
		rc, out, errOut := runAs(t, in.member, "status", "--name", in.n)
		if rc != 0 || !strings.Contains(out, "Not paired") {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out, errOut)
		}
		ss := in.waitState(t, windows.SERVICE_RUNNING, 10*time.Second)
		pid = ss.ProcessId
		t.Logf("status as the member: %s(service pid %d)", out, pid)
	})

	t.Run("the member's tools: not paired, from the service", func(t *testing.T) {
		// Standard input stays open until the answers are in, as an MCP
		// client keeps it.
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		go func() { _, _ = io.WriteString(inW, msgInit+"\n"+msgCall+"\n") }()
		got := make(chan string, 1)
		go func() {
			sc := bufio.NewScanner(outR)
			var lines []string
			for sc.Scan() {
				lines = append(lines, sc.Text())
				if len(lines) == 2 {
					inW.Close()
				}
			}
			got <- strings.Join(lines, "\n")
		}()
		var errOut bytes.Buffer
		rc := 0
		old := mcpIn
		mcpIn = inR
		in.member.as(t, func() { rc = run([]string{"mcp", "--name", in.n}, outW, &errOut) })
		mcpIn = old
		outW.Close()
		out := <-got
		if rc != 0 || !strings.Contains(out, codeNotPaired) {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out, errOut.String())
		}
	})

	t.Run("another user is refused at the channel", func(t *testing.T) {
		rc, _, errOut := runAs(t, other, "status", "--name", in.n)
		if rc != 1 || !strings.Contains(errOut, mcp.TextAccessDenied) {
			t.Fatalf("exit %d, stderr %q", rc, errOut)
		}
	})

	t.Run("an elevated administrator gets status", func(t *testing.T) {
		rc, out, errOut := runAs(t, nil, "status", "--name", in.n)
		if rc != 0 || !strings.Contains(out, "Not paired") {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out, errOut)
		}
	})

	t.Run("the member can't reach the state folder or the process", func(t *testing.T) {
		if _, err := os.Stat(in.stateDir); err != nil {
			t.Fatalf("the service made no state folder: %v", err)
		}
		var readErr, openErr error
		var limited error
		in.member.as(t, func() {
			_, readErr = os.ReadDir(in.stateDir)
			var h windows.Handle
			h, openErr = windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
			if openErr == nil {
				windows.CloseHandle(h)
			}
			h, limited = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
			if limited == nil {
				windows.CloseHandle(h)
			}
		})
		if !errors.Is(readErr, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("the member listing the state folder: %v, want access denied", readErr)
		}
		if !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) {
			t.Fatalf("the member opening the service's process to read it: %v, want access denied", openErr)
		}
		t.Logf("the member: state folder %v; process (read) %v; process (query limited) %v", readErr, openErr, limited)
		sd, err := windows.GetNamedSecurityInfo(in.stateDir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, _ := sd.Owner()
		if owner == nil || owner.String() != in.sid {
			t.Fatalf("the state folder's owner is %v, want the service's account %s", owner, in.sid)
		}
		t.Logf("the state folder: %s", sd.String())
	})

	t.Run("it stops when idle", func(t *testing.T) {
		ss := in.waitState(t, windows.SERVICE_STOPPED, 45*time.Second)
		if ss.Win32ExitCode != 0 {
			t.Fatalf("stopped with %d (service %d)", ss.Win32ExitCode, ss.ServiceSpecificExitCode)
		}
	})

	t.Run("a crash restarts it", func(t *testing.T) {
		if rc, _, errOut := runAs(t, in.member, "status", "--name", in.n); rc != 0 {
			t.Fatalf("status: %d %q", rc, errOut)
		}
		ss := in.waitState(t, windows.SERVICE_RUNNING, 10*time.Second)
		h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, ss.ProcessId)
		if err != nil {
			t.Fatal(err)
		}
		err = windows.TerminateProcess(h, 7)
		windows.CloseHandle(h)
		if err != nil {
			t.Fatal(err)
		}
		for end := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			ss2 := in.query(t)
			if ss2.CurrentState == windows.SERVICE_RUNNING && ss2.ProcessId != ss.ProcessId {
				t.Logf("restarted: pid %d after %d", ss2.ProcessId, ss.ProcessId)
				break
			}
			if time.Now().After(end) {
				t.Fatalf("not restarted: state %d pid %d", ss2.CurrentState, ss2.ProcessId)
			}
		}
		in.stop(t)
	})

	t.Run("a squatted channel name stops it from starting", func(t *testing.T) {
		pipe, err := channel.ReadPipe(in.n)
		if err != nil {
			t.Fatal(err)
		}
		// The squatter lets everyone in, as a hostile one would.
		sd, err := windows.SecurityDescriptorFromString("D:(A;;GA;;;WD)")
		if err != nil {
			t.Fatal(err)
		}
		sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		var h windows.Handle
		other.as(t, func() {
			p, _ := windows.UTF16PtrFromString(channel.PipePath(pipe))
			h, err = windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_BYTE, 1, 4096, 4096, 0, sa)
		})
		if err != nil {
			t.Fatalf("the squatter's pipe: %v", err)
		}
		defer windows.CloseHandle(h)
		// Started by the service manager (at boot, or by an earlier stub),
		// the service finds its name taken and stops with its code.
		if err := in.svc.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		ss := in.waitState(t, windows.SERVICE_STOPPED, 30*time.Second)
		if ss.Win32ExitCode != uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) || ss.ServiceSpecificExitCode != codePipeTaken {
			t.Fatalf("stopped with %d (service %d), want code %d", ss.Win32ExitCode, ss.ServiceSpecificExitCode, codePipeTaken)
		}
		// The member's status reaches the squatter's pipe, refuses it by
		// its owner, and says the service's reason.
		rc, _, errOut := runAs(t, in.member, "status", "--name", in.n)
		if rc != 1 || !strings.Contains(errOut, serviceRefusalText(codePipeTaken)) {
			t.Fatalf("exit %d, stderr %q", rc, errOut)
		}
		t.Logf("status, squatted: %s", errOut)
	})

	t.Run("an account in Administrators refuses to run", func(t *testing.T) {
		admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		group, _, _, err := admins.LookupAccount("")
		if err != nil {
			t.Fatal(err)
		}
		sid, err := windows.StringToSid(in.sid)
		if err != nil {
			t.Fatal(err)
		}
		g, _ := windows.UTF16PtrFromString(group)
		mem := struct{ sid *windows.SID }{sid}
		if r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&mem)), 1); r != 0 {
			t.Fatalf("adding the service's account to Administrators: %d", r)
		}
		defer func() {
			if r, _, _ := procNetLocalGroupDelMembers.Call(0, uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&mem)), 1); r != 0 {
				t.Errorf("removing it: %d", r)
			}
		}()
		rc, _, errOut := runAs(t, in.member, "status", "--name", in.n)
		if rc != 1 || !strings.Contains(errOut, serviceRefusalText(104)) {
			t.Fatalf("exit %d, stderr %q", rc, errOut)
		}
		t.Logf("status, account in Administrators: %s", errOut)
	})

	t.Run("the Event Log", func(t *testing.T) {
		out, err := exec.Command("wevtutil", "qe", "Application", "/q:*[System[Provider[@Name='"+in.name+"']]]", "/f:text", "/c:50").CombinedOutput()
		if err != nil {
			t.Fatalf("wevtutil: %v: %s", err, out)
		}
		text := string(out)
		for _, want := range []string{"pairing " + in.n + ": started", "stopped: idle", "the channel's name is taken", "the service refuses to run"} {
			if !strings.Contains(text, want) {
				t.Errorf("the Event Log has no %q", want)
			}
		}
		if strings.Contains(text, in.member.sid.String()) {
			t.Errorf("the Event Log names the member's SID")
		}
		t.Logf("the Event Log:\n%s", text)
	})
}
