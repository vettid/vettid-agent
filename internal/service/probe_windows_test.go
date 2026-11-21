//go:build windows

package service

// The first check of AGENT-PLAN §6 A3.10b, measured: what a virtual
// service account (NT SERVICE\<name>, SidType unrestricted) holds, and
// how it can start a program as a runner account.
//
// TestServiceAccountProbe registers a throwaway service that runs a copy of
// this test binary as such an account, in the variants of probeVariants:
// by default; with its required privileges cut, with and without
// SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege granted
// through LSA; with only SeAssignPrimaryTokenPrivilege; and with
// SeChangeNotifyPrivilege alone. Inside, the service records its token's
// privileges and tries to start this binary as two throwaway users (one
// with the batch logon right only, one also denied interactive and
// remote logon, as a runner is) two ways: CreateProcessAsUser with a
// batch logon token, and CreateProcessWithLogonW (the secondary logon
// service), without and with the user's profile. Each child records its
// own user; each is started suspended and put in a job that kills it on
// close, and a second child, which waits, shows that closing the job ends
// it. The test checks each variant's outcome where it is known (expect)
// and prints the whole record.
//
// It runs only with VETTID_AGENT_TEST_OTHER_USER=1 (the elevated Windows CI
// step). It removes the service, the rights it granted, the users and
// their profiles, and the folder, and reports what of that fails. It also
// tries to delete the profile Windows makes for the service's virtual
// account; that profile stays "in use" well after the service is deleted
// (measured here: over a minute, even for a service that never started),
// so one left behind is recorded, not failed. The runner is GitHub's
// throwaway machine; on a member's computer the uninstaller (A5.5) has to
// deal with it.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/vettid/vettid-agent/internal/channel"
)

const otherUserEnv = "VETTID_AGENT_TEST_OTHER_USER"

var (
	modadvapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy           = modadvapi32.NewProc("LsaOpenPolicy")
	procLsaAddAccountRights     = modadvapi32.NewProc("LsaAddAccountRights")
	procLsaRemoveAccountRights  = modadvapi32.NewProc("LsaRemoveAccountRights")
	procLsaClose                = modadvapi32.NewProc("LsaClose")
	procLogonUserW              = modadvapi32.NewProc("LogonUserW")
	procLookupPrivilegeNameW    = modadvapi32.NewProc("LookupPrivilegeNameW")
	procCreateProcessWithLogonW = modadvapi32.NewProc("CreateProcessWithLogonW")
	procAdjustTokenPrivileges   = modadvapi32.NewProc("AdjustTokenPrivileges")
	modnetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = modnetapi32.NewProc("NetUserAdd")
	procNetUserDel              = modnetapi32.NewProc("NetUserDel")
	procDeleteProfileW          = windows.NewLazySystemDLL("userenv.dll").NewProc("DeleteProfileW")
)

// errServicePrivilege: a privilege the service requires isn't in its
// account's configuration (ERROR_SERVICE_... 1297).
const errServicePrivilege = syscall.Errno(1297)

// The child's flags (TestProbeChildHelper).
var (
	childOut  = flag.String("probe-child-out", "", "probe child: write this process's user SID here")
	childWait = flag.Bool("probe-child-wait", false, "probe child: wait until killed")
)

// TestProbeChildHelper is the program the service starts as a runner: it
// writes its own user's SID, or waits to be killed.
func TestProbeChildHelper(t *testing.T) {
	if *childOut == "" && !*childWait {
		t.Skip("started by the probe's service")
	}
	if *childWait {
		time.Sleep(5 * time.Minute)
		os.Exit(9)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		os.Exit(4)
	}
	if os.WriteFile(*childOut, []byte(u.User.Sid.String()), 0o600) != nil {
		os.Exit(5)
	}
	os.Exit(0)
}

// probeUser is a throwaway runner the service starts programs as.
type probeUser struct {
	Name     string `json:"name"`
	SID      string `json:"sid"`
	Password string `json:"password"` // throwaway, deleted with the user
	OutDir   string `json:"out_dir"`  // writable by this user only
}

// probeConfig is what the test hands the service, in a file only the
// service's account and administrators can read.
type probeConfig struct {
	Out   string               `json:"out"`
	Exe   string               `json:"exe"`
	Users map[string]probeUser `json:"users"` // "plain", "denied"
}

// startResult is one way of starting a program as one user.
type startResult struct {
	Start     string `json:"start"`      // "ok" or the error
	ChildUser string `json:"child_user"` // the SID the child wrote, or why not
	Exit      string `json:"exit"`
	JobKill   string `json:"job_kill"` // "ok": closing the job ended a waiting child
}

// probeResult is what the service records.
type probeResult struct {
	User              string                 `json:"user"`
	Privileges        []string               `json:"privileges"` // name, "+" if enabled
	ImpersonateAbsent bool                   `json:"impersonate_absent"`
	TcbAbsent         bool                   `json:"tcb_absent"`
	EnableAssign      string                 `json:"enable_assign_primary_token"`
	EnableQuota       string                 `json:"enable_increase_quota"`
	Starts            map[string]startResult `json:"starts"` // "<way>/<user>"
	DPAPI             string                 `json:"dpapi"`
}

// TestServiceAccountProbeHelper is the service's side, run by the SCM.
func TestServiceAccountProbeHelper(t *testing.T) {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		t.Skip("run by TestServiceAccountProbe, as a service")
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "probe.json"))
	if err != nil {
		os.Exit(3)
	}
	var c probeConfig
	if json.Unmarshal(b, &c) != nil {
		os.Exit(3)
	}
	_ = svc.Run("", &probeService{c: c})
	os.Exit(0)
}

type probeService struct{ c probeConfig }

func (p *probeService) Execute(_ []string, _ <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.Running}
	res := runProbe(p.c)
	b, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(p.c.Out, b, 0o600)
	s <- svc.Status{State: svc.StopPending}
	return false, 0
}

func runProbe(c probeConfig) probeResult {
	res := probeResult{Starts: map[string]startResult{}}
	tok := windows.GetCurrentProcessToken()
	if u, err := tok.GetTokenUser(); err == nil {
		res.User = u.User.Sid.String()
	}
	res.ImpersonateAbsent, res.TcbAbsent = true, true
	for _, name := range tokenPrivileges(tok) {
		res.Privileges = append(res.Privileges, name)
		switch strings.TrimSuffix(name, "+") {
		case "SeImpersonatePrivilege":
			res.ImpersonateAbsent = false
		case "SeTcbPrivilege":
			res.TcbAbsent = false
		}
	}
	var proc windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &proc); err != nil {
		res.EnableAssign = err.Error()
		return res
	}
	defer proc.Close()
	res.EnableAssign = errString(setPrivilege(proc, "SeAssignPrimaryTokenPrivilege", true))
	res.EnableQuota = errString(setPrivilege(proc, "SeIncreaseQuotaPrivilege", true))
	for _, who := range []string{"plain", "denied"} {
		u := c.Users[who]
		res.Starts["asuser/"+who] = startAsUser(c.Exe, u)
		res.Starts["withlogon/"+who] = startWithLogon(c.Exe, u, 0)
		res.Starts["withlogon-profile/"+who] = startWithLogon(c.Exe, u, 1 /* LOGON_WITH_PROFILE */)
	}
	res.DPAPI = errString(dpapiRoundTrip())
	return res
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// starter starts the probe's binary suspended with these arguments and
// returns its process information.
type starter func(args string) (windows.ProcessInformation, error)

// startAsUser uses CreateProcessAsUser with a batch logon token of u.
func startAsUser(exe string, u probeUser) startResult {
	var tok windows.Token
	n, _ := windows.UTF16PtrFromString(u.Name)
	dot, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(u.Password)
	if r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pw)),
		4 /* LOGON32_LOGON_BATCH */, 0, uintptr(unsafe.Pointer(&tok))); r == 0 {
		return startResult{Start: "batch logon: " + e.Error()}
	}
	defer tok.Close()
	return runChildren(exe, u, func(args string) (windows.ProcessInformation, error) {
		cl, _ := windows.UTF16PtrFromString(`"` + exe + `" ` + args)
		si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
		var pi windows.ProcessInformation
		err := windows.CreateProcessAsUser(tok, nil, cl, nil, nil, false, windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED, nil, nil, si, &pi)
		return pi, err
	})
}

// startWithLogon uses CreateProcessWithLogonW (the secondary logon
// service), which logs the user on interactively.
func startWithLogon(exe string, u probeUser, logonFlags uintptr) startResult {
	return runChildren(exe, u, func(args string) (windows.ProcessInformation, error) {
		n, _ := windows.UTF16PtrFromString(u.Name)
		dot, _ := windows.UTF16PtrFromString(".")
		pw, _ := windows.UTF16PtrFromString(u.Password)
		cl, _ := windows.UTF16FromString(`"` + exe + `" ` + args) // writable, as the API needs
		dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
		si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
		var pi windows.ProcessInformation
		r, _, e := procCreateProcessWithLogonW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pw)),
			logonFlags, 0, uintptr(unsafe.Pointer(&cl[0])), uintptr(windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED), 0,
			uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(&pi)))
		if r == 0 {
			return pi, e
		}
		return pi, nil
	})
}

// runChildren starts a child that writes its user, in a job that kills on
// close, and waits for it; then a child that waits, in a job that is then
// closed, and checks it ended.
func runChildren(exe string, u probeUser, start starter) startResult {
	var res startResult
	out := filepath.Join(u.OutDir, "user.txt")
	pi, err := start(`-test.run=^TestProbeChildHelper$ -probe-child-out="` + out + `"`)
	if err != nil {
		res.Start = err.Error()
		return res
	}
	res.Start = "ok"
	job, jerr := killOnCloseJob()
	if jerr == nil {
		jerr = windows.AssignProcessToJobObject(job, pi.Process)
	}
	if jerr != nil {
		res.JobKill = "job: " + jerr.Error()
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		res.Exit = "resume: " + err.Error()
	}
	res.Exit = waitExit(pi, 60*time.Second)
	if b, err := os.ReadFile(out); err == nil {
		res.ChildUser = string(b)
	} else {
		res.ChildUser = "not written: " + err.Error()
	}
	if job != 0 {
		windows.CloseHandle(job)
	}
	if res.JobKill != "" {
		return res
	}
	// A waiting child, killed by closing its job.
	pi, err = start(`-test.run=^TestProbeChildHelper$ -probe-child-wait`)
	if err != nil {
		res.JobKill = "start: " + err.Error()
		return res
	}
	job, jerr = killOnCloseJob()
	if jerr == nil {
		jerr = windows.AssignProcessToJobObject(job, pi.Process)
	}
	if jerr != nil {
		res.JobKill = "job: " + jerr.Error()
		_ = windows.TerminateProcess(pi.Process, 1)
		waitExit(pi, 10*time.Second)
		return res
	}
	_, _ = windows.ResumeThread(pi.Thread)
	time.Sleep(500 * time.Millisecond)
	windows.CloseHandle(job)
	if ev, err := windows.WaitForSingleObject(pi.Process, 10000); err != nil || ev != windows.WAIT_OBJECT_0 {
		res.JobKill = "still running 10 s after its job was closed"
		_ = windows.TerminateProcess(pi.Process, 1)
	} else {
		res.JobKill = "ok"
	}
	waitExit(pi, 10*time.Second)
	return res
}

// waitExit waits for the process, ends it if it doesn't end in time, and
// closes its handles; it returns how it ended.
func waitExit(pi windows.ProcessInformation, d time.Duration) string {
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	ev, err := windows.WaitForSingleObject(pi.Process, uint32(d.Milliseconds()))
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		_ = windows.TerminateProcess(pi.Process, 1)
		return fmt.Sprintf("did not end within %s; terminated", d)
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		return "exit code: " + err.Error()
	}
	return fmt.Sprintf("exit %#x", code)
}

func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// tokenPrivileges lists the token's privileges by name, "+" marking an
// enabled one.
func tokenPrivileges(tok windows.Token) []string {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &n)
	if n == 0 {
		return nil
	}
	buf := make([]byte, n)
	if windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], n, &n) != nil {
		return nil
	}
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	var out []string
	for _, p := range tp.AllPrivileges() {
		name := make([]uint16, 64)
		l := uint32(len(name))
		if r, _, _ := procLookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(&p.Luid)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&l))); r == 0 {
			continue
		}
		s := windows.UTF16ToString(name[:l])
		if p.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
			s += "+"
		}
		out = append(out, s)
	}
	return out
}

// setPrivilege enables or disables a privilege of tok. A privilege the
// token lacks is ERROR_NOT_ALL_ASSIGNED, which AdjustTokenPrivileges
// reports together with success; x/sys's wrapper returns an error only
// when the call fails, so the call is made here and its error read from
// the same call.
func setPrivilege(tok windows.Token, name string, enable bool) error {
	var luid windows.LUID
	n, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid}
	if enable {
		tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	}
	r, _, e := procAdjustTokenPrivileges.Call(uintptr(tok), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r == 0 {
		return e
	}
	if errors.Is(e, windows.ERROR_NOT_ALL_ASSIGNED) {
		return fmt.Errorf("%s: not held by this token", name)
	}
	return nil
}

func dpapiRoundTrip() error {
	in := []byte("probe")
	var out windows.DataBlob
	if err := windows.CryptProtectData(&windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}, nil, nil, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return fmt.Errorf("protect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	var back windows.DataBlob
	if err := windows.CryptUnprotectData(&out, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &back); err != nil {
		return fmt.Errorf("unprotect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(back.Data)))
	if string(unsafe.Slice(back.Data, back.Size)) != "probe" {
		return errors.New("round trip changed the data")
	}
	return nil
}

// lsaUnicode is an LSA_UNICODE_STRING.
type lsaUnicode struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

// lsaRight adds (or removes) an account right for sid.
func lsaRight(sid *windows.SID, right string, add bool) error {
	var attrs [12]uintptr // LSA_OBJECT_ATTRIBUTES, zeroed
	var policy uintptr
	if st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs[0])), 0x00000800|0x00000010 /* POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT */, uintptr(unsafe.Pointer(&policy))); st != 0 {
		return fmt.Errorf("LsaOpenPolicy: NTSTATUS %#x", st)
	}
	defer procLsaClose.Call(policy)
	u, _ := windows.UTF16FromString(right)
	r := lsaUnicode{Length: uint16(2 * (len(u) - 1)), MaximumLength: uint16(2 * len(u)), Buffer: &u[0]}
	var st uintptr
	if add {
		st, _, _ = procLsaAddAccountRights.Call(policy, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&r)), 1)
	} else {
		st, _, _ = procLsaRemoveAccountRights.Call(policy, uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(&r)), 1)
	}
	if st != 0 {
		return fmt.Errorf("LSA account right %s: NTSTATUS %#x", right, st)
	}
	return nil
}

type userInfo1 struct {
	name, password *uint16
	passwordAge    uint32
	priv           uint32
	homeDir        *uint16
	comment        *uint16
	flags          uint32
	scriptPath     *uint16
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// protectDir gives path a protected access list from sddl.
func protectDir(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// deleteProfile removes the profile Windows made for a test user, if any:
// a profile is unloaded a little after its last process ends, so it is
// tried for 30 s, and a failure is reported.
func deleteProfile(t *testing.T, sid string) {
	if err := tryDeleteProfile(sid, 30*time.Second); err != nil {
		t.Errorf("DeleteProfile %s: %v", sid, err)
	}
}

// newProbeUser makes a throwaway local user with the batch logon right
// (and, if denied, denied interactive and remote logon), and a folder
// only it can write; all removed when the test ends.
func newProbeUser(t *testing.T, dir, svcSID string, denied bool) probeUser {
	t.Helper()
	name := "vtdp" + randHex(4)
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	pass := base64.RawURLEncoding.EncodeToString(pw) + "Aa1!"
	un, _ := windows.UTF16PtrFromString(name)
	up, _ := windows.UTF16PtrFromString(pass)
	info := userInfo1{name: un, password: up, priv: 1, flags: 0x1 | 0x10000}
	var parm uint32
	if r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm))); r != 0 {
		t.Fatalf("NetUserAdd: %d", r)
	}
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		deleteProfile(t, sid.String())
		if r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(un))); r != 0 {
			t.Errorf("NetUserDel %s: %d", name, r)
		}
	})
	rights := []string{"SeBatchLogonRight"}
	if denied {
		rights = append(rights, "SeDenyInteractiveLogonRight", "SeDenyRemoteInteractiveLogonRight")
	}
	for _, right := range rights {
		if err := lsaRight(sid, right, true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := lsaRight(sid, right, false); err != nil {
				t.Errorf("removing %s: %v", right, err)
			}
		})
	}
	out := filepath.Join(dir, "out-"+name)
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	// The user writes here; the service reads what its child wrote.
	protectDir(t, out, "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;"+sid.String()+")(A;OICI;FR;;;"+svcSID+")")
	return probeUser{Name: name, SID: sid.String(), Password: pass, OutDir: out}
}

// probeVariant: the service's required privileges (none: the default
// set), and the rights granted to its account through LSA first. expect
// checks the record where the outcome is known; nil records only.
type probeVariant struct {
	name     string
	required []string
	grant    []string
	startErr error // the service must not start, with this error
	expect   func(t *testing.T, r probeResult, users map[string]probeUser)
}

var probeVariants = []probeVariant{
	{name: "default", expect: func(t *testing.T, r probeResult, _ map[string]probeUser) {
		if r.ImpersonateAbsent {
			t.Error("default: SeImpersonatePrivilege absent; expected present")
		}
		for _, k := range []string{"asuser/plain", "asuser/denied"} {
			if r.Starts[k].Start == "ok" {
				t.Errorf("default: %s started; expected refused", k)
			}
		}
		if r.DPAPI != "ok" {
			t.Errorf("default: DPAPI: %s", r.DPAPI)
		}
	}},
	{name: "cut3", required: []string{"SeChangeNotifyPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"},
		startErr: errServicePrivilege},
	{name: "cut3+grant2", required: []string{"SeChangeNotifyPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"},
		grant: []string{"SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"},
		expect: func(t *testing.T, r probeResult, users map[string]probeUser) {
			want := []string{"SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeChangeNotifyPrivilege+"}
			if !sameSet(r.Privileges, want) {
				t.Errorf("cut3+grant2: privileges %v, want %v (as the service starts, before the probe enables them)", r.Privileges, want)
			}
			if !r.ImpersonateAbsent || !r.TcbAbsent {
				t.Error("cut3+grant2: SeImpersonatePrivilege or SeTcbPrivilege held")
			}
			for _, who := range []string{"plain", "denied"} {
				checkStart(t, "cut3+grant2", "asuser/"+who, r.Starts["asuser/"+who], users[who])
			}
			if r.DPAPI != "ok" {
				t.Errorf("cut3+grant2: DPAPI: %s", r.DPAPI)
			}
		}},
	// SeAssignPrimaryTokenPrivilege alone is enough for CreateProcessAsUser
	// with a batch logon token.
	{name: "cut2+grant1", required: []string{"SeChangeNotifyPrivilege", "SeAssignPrimaryTokenPrivilege"},
		grant: []string{"SeAssignPrimaryTokenPrivilege"},
		expect: func(t *testing.T, r probeResult, users map[string]probeUser) {
			if !sameSet(r.Privileges, []string{"SeAssignPrimaryTokenPrivilege", "SeChangeNotifyPrivilege+"}) || !r.ImpersonateAbsent || !r.TcbAbsent {
				t.Errorf("cut2+grant1: privileges %v", r.Privileges)
			}
			for _, who := range []string{"plain", "denied"} {
				checkStart(t, "cut2+grant1", "asuser/"+who, r.Starts["asuser/"+who], users[who])
			}
		}},
	// With no special privilege, CreateProcessAsUser is refused, and
	// CreateProcessWithLogonW (an interactive logon) works only for a user
	// who may log on interactively: not for a runner denied it.
	{name: "cut1", required: []string{"SeChangeNotifyPrivilege"},
		expect: func(t *testing.T, r probeResult, users map[string]probeUser) {
			if !sameSet(r.Privileges, []string{"SeChangeNotifyPrivilege+"}) {
				t.Errorf("cut1: privileges %v", r.Privileges)
			}
			for _, who := range []string{"plain", "denied"} {
				if r.Starts["asuser/"+who].Start == "ok" {
					t.Errorf("cut1: asuser/%s started", who)
				}
			}
			for _, way := range []string{"withlogon", "withlogon-profile"} {
				checkStart(t, "cut1", way+"/plain", r.Starts[way+"/plain"], users["plain"])
				if s := r.Starts[way+"/denied"]; !strings.Contains(s.Start, "logon type") {
					t.Errorf("cut1: %s/denied: %+v, want refused for the logon type", way, s)
				}
			}
		}},
}

func checkStart(t *testing.T, variant, key string, s startResult, u probeUser) {
	t.Helper()
	if s.Start != "ok" || s.ChildUser != u.SID || s.Exit != "exit 0x0" || s.JobKill != "ok" {
		t.Errorf("%s: %s: %+v, want started, child running as %s, exit 0, killed with its job", variant, key, s, u.SID)
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// TestServiceAccountProbe: see the file's comment.
func TestServiceAccountProbe(t *testing.T) {
	if os.Getenv(otherUserEnv) != "1" {
		t.Skipf("set %s=1 to register a test service and users (CI only)", otherUserEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%s=1 needs an elevated (administrator) process", otherUserEnv)
	}
	// The secondary logon service, for CreateProcessWithLogonW.
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService("seclogon"); err == nil {
		if c, err := s.Config(); err == nil && c.StartType == mgr.StartDisabled {
			c.StartType = mgr.StartManual
			_ = s.UpdateConfig(c)
		}
		_ = s.Start()
		s.Close()
	}
	for _, v := range probeVariants {
		t.Run(v.name, func(t *testing.T) { probeOnce(t, m, v) })
	}
}

func probeOnce(t *testing.T, m *mgr.Mgr, v probeVariant) {
	name := "vettid-probe-" + randHex(4)
	svcSID, err := windows.StringToSid(channel.ServiceSID(name))
	if err != nil {
		t.Fatal(err)
	}
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(pd, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("removing %s: %v", dir, err)
		}
	})
	// The folder: administrators, SYSTEM and the service's account; the
	// binary readable by Users, for the children.
	protectDir(t, dir, "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;"+svcSID.String()+")(A;OICI;0x1200a9;;;BU)")
	users := map[string]probeUser{"plain": newProbeUser(t, dir, svcSID.String(), false), "denied": newProbeUser(t, dir, svcSID.String(), true)}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "probe.exe")
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	// The configuration holds the users' passwords: its own protected
	// access list, administrators, SYSTEM and the service's account only.
	cfgPath := filepath.Join(dir, "probe.json")
	out := filepath.Join(dir, "result.json")
	cfg, _ := json.Marshal(probeConfig{Out: out, Exe: exe, Users: users})
	if err := os.WriteFile(cfgPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	protectDir(t, cfgPath, "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;"+svcSID.String()+")")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, right := range v.grant {
		if err := lsaRight(svcSID, right, true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := lsaRight(svcSID, right, false); err != nil {
				t.Errorf("removing %s: %v", right, err)
			}
		})
	}

	s, err := m.CreateService(name, exe, mgr.Config{
		DisplayName:      name,
		StartType:        mgr.StartManual,
		ServiceStartName: `NT SERVICE\` + name,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "-test.run=^TestServiceAccountProbeHelper$")
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	t.Cleanup(func() { removeService(t, m, s, name, svcSID.String()) })
	if v.required != nil {
		// A multi-string: each name NUL-terminated, then one more NUL
		// (UTF16FromString refuses a string with NULs in it).
		privs := utf16.Encode([]rune(strings.Join(v.required, "\x00") + "\x00\x00"))
		type requiredPrivilegesInfo struct{ privileges *uint16 }
		rp := requiredPrivilegesInfo{&privs[0]}
		if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&rp))); err != nil {
			t.Fatalf("required privileges: %v", err)
		}
	}
	err = s.Start()
	if v.startErr != nil {
		if !errors.Is(err, v.startErr) {
			t.Errorf("%s: start: %v, want %v", v.name, err, v.startErr)
		} else {
			t.Logf("%s: service %s did not start, as expected: %v (%d)", v.name, name, err, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: start: %v (%d)", v.name, err, err)
	}
	var rec []byte
	for end := time.Now().Add(4 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
		if rec, err = os.ReadFile(out); err == nil && len(rec) > 0 {
			break
		}
		if time.Now().After(end) {
			st, _ := s.Query()
			t.Fatalf("no record from the service (state %d, exit %d, service exit %d)", st.State, st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
	}
	t.Logf("%s: service %s (%s), users plain %s, denied %s\n%s", v.name, name, svcSID, users["plain"].SID, users["denied"].SID, rec)
	var res probeResult
	if err := json.Unmarshal(rec, &res); err != nil {
		t.Fatal(err)
	}
	if v.expect != nil {
		v.expect(t, res, users)
	}
}

// removeService stops the service, waits until it has stopped, deletes it,
// checks it is gone, and removes the profile Windows made for its account.
func removeService(t *testing.T, m *mgr.Mgr, s *mgr.Service, name, sid string) {
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			t.Logf("stopping %s: %v", name, err)
		}
		for end := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			if time.Now().After(end) {
				t.Errorf("%s did not stop", name)
				break
			}
		}
	}
	if err := s.Delete(); err != nil {
		t.Errorf("deleting %s: %v", name, err)
	}
	s.Close()
	for end := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		s2, err := m.OpenService(name)
		if err != nil {
			break // gone
		}
		s2.Close()
		if time.Now().After(end) {
			t.Errorf("%s is still registered after its deletion", name)
			break
		}
	}
	if err := tryDeleteProfile(sid, 10*time.Second); err != nil {
		t.Logf("the profile of %s (%s) is left behind: %v", name, sid, err)
	}
}

// tryDeleteProfile deletes sid's profile, retrying while it is in use,
// for at most d.
func tryDeleteProfile(sid string, d time.Duration) error {
	p, _ := windows.UTF16PtrFromString(sid)
	for end := time.Now().Add(d); ; time.Sleep(time.Second) {
		r, _, e := procDeleteProfileW.Call(uintptr(unsafe.Pointer(p)), 0, 0)
		if r != 0 || errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return nil
		}
		if !errors.Is(e, windows.ERROR_SHARING_VIOLATION) || time.Now().After(end) {
			return e
		}
	}
}
