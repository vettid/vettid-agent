//go:build windows

package service

// The first check of AGENT-PLAN §6 A3.10b, measured: can a virtual service
// account (NT SERVICE\<name>, SidType unrestricted) hold and use
// SeAssignPrimaryTokenPrivilege, which CreateProcessAsUser needs to start
// a run as a runner account? The answer decides between the virtual
// account and a local user with the service logon right.
//
// TestServiceAccountProbe registers a throwaway service that runs a copy of
// this test binary as such an account, twice: without and with the
// privilege granted to the account through LSA, both times with the
// service's required privileges cut to SeChangeNotifyPrivilege,
// SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege. Inside, the
// service records its token's privileges, whether SeImpersonatePrivilege
// is absent, whether CreateProcessAsUser starts a program as a throwaway
// user (batch logon), and a DPAPI round trip; the test prints the record.
// It runs only with VETTID_AGENT_TEST_OTHER_USER=1 (the elevated Windows CI
// step) and removes everything it made.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	modadvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy         = modadvapi32.NewProc("LsaOpenPolicy")
	procLsaAddAccountRights   = modadvapi32.NewProc("LsaAddAccountRights")
	procLsaRemoveAccountRight = modadvapi32.NewProc("LsaRemoveAccountRights")
	procLsaClose              = modadvapi32.NewProc("LsaClose")
	procLogonUserW            = modadvapi32.NewProc("LogonUserW")
	procLookupPrivilegeNameW  = modadvapi32.NewProc("LookupPrivilegeNameW")
	modnetapi32               = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd            = modnetapi32.NewProc("NetUserAdd")
	procNetUserDel            = modnetapi32.NewProc("NetUserDel")
)

// probeConfig is what the test hands the service, in a file next to its
// binary that only the service's account and administrators can read.
type probeConfig struct {
	Out      string `json:"out"`
	User     string `json:"user"`
	Password string `json:"password"` // a throwaway user's, deleted with it
	Child    string `json:"child"`
}

// probeResult is what the service records.
type probeResult struct {
	User              string   `json:"user"`
	Privileges        []string `json:"privileges"` // name, then "+" if enabled
	ImpersonateAbsent bool     `json:"impersonate_absent"`
	TcbAbsent         bool     `json:"tcb_absent"`
	EnableAssign      string   `json:"enable_assign_primary_token"`
	LogonBatch        string   `json:"logon_batch"`
	// CreateAsUser is CreateProcessAsUser with SeAssignPrimaryTokenPrivilege
	// enabled and SeIncreaseQuotaPrivilege not; CreateAsUserQuota with both.
	CreateAsUser      string `json:"create_process_as_user_assign_only"`
	EnableQuota       string `json:"enable_increase_quota"`
	CreateAsUserQuota string `json:"create_process_as_user_assign_and_quota"`
	ChildExit         string `json:"child_exit"`
	DPAPI             string `json:"dpapi"`
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

func (p *probeService) Execute(_ []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}
	res := runProbe(p.c)
	b, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(p.c.Out, b, 0o600)
	s <- svc.Status{State: svc.StopPending}
	return false, 0
}

func runProbe(c probeConfig) probeResult {
	var res probeResult
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
	// SeIncreaseQuotaPrivilege off for the first try.
	_ = setPrivilege(proc, "SeIncreaseQuotaPrivilege", false)
	var user windows.Token
	n, _ := windows.UTF16PtrFromString(c.User)
	dot, _ := windows.UTF16PtrFromString(".")
	pw, _ := windows.UTF16PtrFromString(c.Password)
	if r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(pw)),
		4 /* LOGON32_LOGON_BATCH */, 0, uintptr(unsafe.Pointer(&user))); r == 0 {
		res.LogonBatch = e.Error()
	} else {
		res.LogonBatch = "ok"
		defer user.Close()
		res.CreateAsUser, _ = startAs(user, c.Child)
		res.EnableQuota = errString(setPrivilege(proc, "SeIncreaseQuotaPrivilege", true))
		res.CreateAsUserQuota, res.ChildExit = startAs(user, c.Child)
	}
	res.DPAPI = errString(dpapiRoundTrip())
	return res
}

// startAs starts child as the user of tok (CreateProcessAsUser) and waits
// for it.
func startAs(tok windows.Token, child string) (result, exit string) {
	cl, _ := windows.UTF16PtrFromString(`"` + child + `" -test.run=^$`)
	si := &windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, nil, cl, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, si, &pi); err != nil {
		return err.Error(), ""
	}
	ev, _ := windows.WaitForSingleObject(pi.Process, 30000)
	var code uint32
	_ = windows.GetExitCodeProcess(pi.Process, &code)
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return "ok", fmt.Sprintf("wait %#x, exit %#x", ev, code)
}

func errString(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
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

var procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")

// setPrivilege enables or disables a privilege of tok. A privilege the
// token lacks is ERROR_NOT_ALL_ASSIGNED, which AdjustTokenPrivileges
// reports with success, read here from the same call.
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

func lsaString(s string) lsaUnicode {
	u, _ := windows.UTF16FromString(s)
	return lsaUnicode{Length: uint16(2 * (len(u) - 1)), MaximumLength: uint16(2 * len(u)), Buffer: &u[0]}
}

// lsaRight adds (or removes) an account right for sid.
func lsaRight(sid *windows.SID, right string, add bool) error {
	var attrs [12]uintptr // LSA_OBJECT_ATTRIBUTES, zeroed
	var policy uintptr
	if st, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attrs[0])), 0x00000800|0x00000010 /* POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT */, uintptr(unsafe.Pointer(&policy))); st != 0 {
		return fmt.Errorf("LsaOpenPolicy: NTSTATUS %#x", st)
	}
	defer procLsaClose.Call(policy)
	r := lsaString(right)
	var st uintptr
	if add {
		st, _, _ = procLsaAddAccountRights.Call(policy, uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&r)), 1)
	} else {
		st, _, _ = procLsaRemoveAccountRight.Call(policy, uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(&r)), 1)
	}
	if st != 0 {
		return fmt.Errorf("LSA account rights: NTSTATUS %#x", st)
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

// TestServiceAccountProbe: see the file's comment.
func TestServiceAccountProbe(t *testing.T) {
	if os.Getenv(otherUserEnv) != "1" {
		t.Skipf("set %s=1 to register a test service and users (CI only)", otherUserEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%s=1 needs an elevated (administrator) process", otherUserEnv)
	}
	for _, granted := range []bool{false, true} {
		t.Run(fmt.Sprintf("granted=%v", granted), func(t *testing.T) { probeOnce(t, granted) })
	}
}

func probeOnce(t *testing.T, granted bool) {
	name := "vettid-probe-" + randHex(4)
	svcSID, err := windows.StringToSid(channel.ServiceSID(name))
	if err != nil {
		t.Fatal(err)
	}
	// The throwaway user the service starts a program as, with the batch
	// logon right only.
	user := "vtdp" + randHex(4)
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	pass := base64.RawURLEncoding.EncodeToString(pw) + "Aa1!"
	un, _ := windows.UTF16PtrFromString(user)
	up, _ := windows.UTF16PtrFromString(pass)
	info := userInfo1{name: un, password: up, priv: 1, flags: 0x1 | 0x10000}
	var parm uint32
	if r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm))); r != 0 {
		t.Fatalf("NetUserAdd: %d", r)
	}
	t.Cleanup(func() { procNetUserDel.Call(0, uintptr(unsafe.Pointer(un))) })
	userSID, _, _, err := windows.LookupSID("", user)
	if err != nil {
		t.Fatal(err)
	}
	if err := lsaRight(userSID, "SeBatchLogonRight", true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lsaRight(userSID, "SeBatchLogonRight", false) })

	// The service's folder: its binary, its configuration and its record,
	// for the service's account and administrators; the binary readable
	// by Users too, for the child the service starts as the user.
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(pd, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;" + svcSID.String() + ")(A;OICI;0x1200a9;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
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
	out := filepath.Join(dir, "result.json")
	cfg, _ := json.Marshal(probeConfig{Out: out, User: user, Password: pass, Child: exe})
	if err := os.WriteFile(filepath.Join(dir, "probe.json"), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	if granted {
		if err := lsaRight(svcSID, "SeAssignPrimaryTokenPrivilege", true); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lsaRight(svcSID, "SeAssignPrimaryTokenPrivilege", false) })
	}

	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.CreateService(name, exe, mgr.Config{
		DisplayName:      name,
		StartType:        mgr.StartManual,
		ServiceStartName: `NT SERVICE\` + name,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "-test.run=^TestServiceAccountProbeHelper$")
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	t.Cleanup(func() {
		_, _ = s.Control(svc.Stop)
		_ = s.Delete()
		s.Close()
	})
	// Required privileges: only these three, so the service's token holds
	// no others (SeImpersonatePrivilege in particular).
	// A multi-string: each name NUL-terminated, then one more NUL
	// (UTF16FromString refuses a string with NULs in it).
	privs := utf16.Encode([]rune("SeChangeNotifyPrivilege\x00SeAssignPrimaryTokenPrivilege\x00SeIncreaseQuotaPrivilege\x00\x00"))
	type requiredPrivilegesInfo struct{ privileges *uint16 }
	rp := requiredPrivilegesInfo{&privs[0]}
	if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&rp))); err != nil {
		t.Fatalf("required privileges: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	var rec []byte
	for end := time.Now().Add(60 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if rec, err = os.ReadFile(out); err == nil && len(rec) > 0 {
			break
		}
		if time.Now().After(end) {
			st, _ := s.Query()
			t.Fatalf("no record from the service (state %d, exit %d, service exit %d)", st.State, st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
	}
	t.Logf("SeAssignPrimaryTokenPrivilege granted through LSA: %v; service %s (%s)\n%s", granted, name, svcSID, rec)
	var res probeResult
	if err := json.Unmarshal(rec, &res); err != nil {
		t.Fatal(err)
	}
	if !res.ImpersonateAbsent {
		t.Error("the service holds SeImpersonatePrivilege despite its required privileges")
	}
}
