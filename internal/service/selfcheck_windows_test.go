//go:build windows

package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
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

const testServiceSID = "S-1-5-80-1-2-3-4-5"

func okToken() Token {
	return Token{
		User:       testServiceSID,
		Privileges: []string{changeNotify},
		Groups: []Group{
			{SID: "S-1-16-12288", Attributes: 0x60},
			{SID: "S-1-1-0", Attributes: 7},
			{SID: "S-1-5-32-545", Attributes: 7},
			{SID: "S-1-5-6", Attributes: 7},
			{SID: "S-1-5-5-0-123456", Attributes: 0xc0000007},
			{SID: "S-1-2-0", Attributes: 7},
			{SID: "S-1-2-1", Attributes: 7},
			{SID: "S-1-5-11", Attributes: 7},
			{SID: "S-1-5-15", Attributes: 7},
			{SID: "S-1-5-80-0", Attributes: 7},
		},
	}
}

func checkCode(t *testing.T, tok Token, want uint32) {
	t.Helper()
	err := Check(tok, testServiceSID)
	if want == 0 {
		if err != nil {
			t.Fatalf("Check = %v, want nil", err)
		}
		return
	}
	var ce *CheckError
	if !errors.As(err, &ce) || ce.Code != want {
		t.Fatalf("Check = %v, want code %d", err, want)
	}
}

func TestCheck(t *testing.T) {
	checkCode(t, okToken(), 0)

	// No privilege at all is not more than ChangeNotify.
	tok := okToken()
	tok.Privileges = nil
	checkCode(t, tok, 0)

	for _, p := range []string{"SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege",
		"SeTcbPrivilege", "SeCreateGlobalPrivilege", "SeIncreaseWorkingSetPrivilege", "SeSomeFuturePrivilege"} {
		tok := okToken()
		tok.Privileges = append(tok.Privileges, p)
		checkCode(t, tok, CodePrivileges)
		if err := Check(tok, testServiceSID); !strings.Contains(err.Error(), p) {
			t.Fatalf("%s: %v does not name it", p, err)
		}
	}

	// Administrators, enabled or deny-only.
	for _, attr := range []uint32{7, 0x10 /* SE_GROUP_USE_FOR_DENY_ONLY */} {
		tok := okToken()
		tok.Groups = append(tok.Groups, Group{SID: "S-1-5-32-544", Attributes: attr})
		checkCode(t, tok, CodeAdministrators)
	}

	for _, g := range []string{"S-1-5-32-547" /* Power Users */, "S-1-5-21-1-2-3-1001", "S-1-5-80-9-9-9-9-9",
		"S-1-5-5-0", "S-1-5-5-x-1", "S-1-16-8192" /* a label SID without the label attribute */, "S-1-5-4" /* INTERACTIVE */} {
		tok := okToken()
		tok.Groups = append(tok.Groups, Group{SID: g, Attributes: 7})
		checkCode(t, tok, CodeExtraGroup)
	}

	// Beyond the measured set: another label, a label SID without the
	// label's attribute, a second logon SID, a logon SID not marked as
	// one, and the service's own SID as a group.
	for _, g := range []Group{
		{SID: "S-1-16-16384", Attributes: 0x60},
		{SID: "S-1-16-8192", Attributes: 0x60},
		{SID: "S-1-5-5-0-999", Attributes: 0xc0000007},
		{SID: testServiceSID, Attributes: 0xe},
	} {
		tok := okToken()
		tok.Groups = append(tok.Groups, g)
		checkCode(t, tok, CodeExtraGroup)
	}
	tok = okToken()
	for i, g := range tok.Groups {
		if isLogonSID(g.SID) {
			tok.Groups[i].Attributes = 7
		}
	}
	checkCode(t, tok, CodeExtraGroup)

	tok = okToken()
	tok.User = "S-1-5-80-9-9-9-9-9"
	checkCode(t, tok, CodeWrongAccount)
	tok.User = "S-1-5-18"
	checkCode(t, tok, CodeWrongAccount)
}

// The token of this test process reads.
func TestReadTokenSelf(t *testing.T) {
	tok, err := ReadToken(windows.GetCurrentProcessToken())
	if err != nil {
		t.Fatal(err)
	}
	if tok.User == "" || len(tok.Groups) == 0 || !slices.Contains(tok.Privileges, changeNotify) {
		t.Fatalf("read %+v", tok)
	}
	// This process is not the service: the check says so first.
	checkCode(t, tok, CodeWrongAccount)
}

// selfCheckConfig is what TestSelfCheckService gives its service, in a
// file next to the binary.
type selfCheckConfig struct {
	Name string `json:"name"`
	Out  string `json:"out"`
}

type selfCheckResult struct {
	Token Token  `json:"token"`
	Code  uint32 `json:"code"`
	Error string `json:"error"`
}

// TestSelfCheckServiceHelper is the service's side, run by the SCM.
func TestSelfCheckServiceHelper(t *testing.T) {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		t.Skip("run by TestSelfCheckService, as a service")
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "selfcheck.json"))
	if err != nil {
		os.Exit(3)
	}
	var c selfCheckConfig
	if json.Unmarshal(b, &c) != nil {
		os.Exit(3)
	}
	_ = svc.Run("", &selfCheckService{c: c})
	os.Exit(0)
}

type selfCheckService struct{ c selfCheckConfig }

func (p *selfCheckService) Execute(_ []string, _ <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	s <- svc.Status{State: svc.Running}
	tok, err := SelfCheck(p.c.Name)
	res := selfCheckResult{Token: tok}
	var ce *CheckError
	if errors.As(err, &ce) {
		res.Code, res.Error = ce.Code, ce.Error()
	} else if err != nil {
		res.Error = err.Error()
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	_ = os.WriteFile(p.c.Out, b, 0o600)
	s <- svc.Status{State: svc.StopPending}
	return false, 0
}

var (
	procNetLocalGroupAdd        = modnetapi32.NewProc("NetLocalGroupAdd")
	procNetLocalGroupDel        = modnetapi32.NewProc("NetLocalGroupDel")
	procNetLocalGroupAddMembers = modnetapi32.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMembers = modnetapi32.NewProc("NetLocalGroupDelMembers")
)

// addToGroup adds sid to the local group named group, and removes it
// when the test ends.
func addToGroup(t *testing.T, group string, sid *windows.SID) {
	t.Helper()
	g, _ := windows.UTF16PtrFromString(group)
	m := struct{ sid *windows.SID }{sid}
	if r, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&m)), 1); r != 0 {
		t.Fatalf("adding %s to %s: %d", sid, group, r)
	}
	t.Cleanup(func() {
		if r, _, _ := procNetLocalGroupDelMembers.Call(0, uintptr(unsafe.Pointer(g)), 0, uintptr(unsafe.Pointer(&m)), 1); r != 0 {
			t.Errorf("removing %s from %s: %d", sid, group, r)
		}
	})
}

// newLocalGroup makes a throwaway local group and returns its name and
// SID; it is removed when the test ends.
func newLocalGroup(t *testing.T) (string, string) {
	t.Helper()
	name := "vtestgrp" + randHex(4)
	n, _ := windows.UTF16PtrFromString(name)
	info := struct{ name *uint16 }{n}
	var parm uint32
	if r, _, _ := procNetLocalGroupAdd.Call(0, 0, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm))); r != 0 {
		t.Fatalf("NetLocalGroupAdd: %d", r)
	}
	t.Cleanup(func() {
		if r, _, _ := procNetLocalGroupDel.Call(0, uintptr(unsafe.Pointer(n))); r != 0 {
			t.Errorf("NetLocalGroupDel %s: %d", name, r)
		}
	})
	sid, _, _, err := windows.LookupSID("", name)
	if err != nil {
		t.Fatal(err)
	}
	return name, sid.String()
}

type selfCheckVariant struct {
	name string
	// cut: the required-privileges list cut to SeChangeNotifyPrivilege, as
	// the installer sets it.
	cut bool
	// group: a local group the service's account is added to ("admins"
	// for Administrators, "new" for a throwaway group).
	group  string
	expect func(t *testing.T, r selfCheckResult, groupSID string)
}

var selfCheckVariants = []selfCheckVariant{
	{name: "cut1", cut: true, expect: func(t *testing.T, r selfCheckResult, _ string) {
		if r.Code != 0 || r.Error != "" {
			t.Fatalf("the installed shape was refused: %d %s", r.Code, r.Error)
		}
		if !slices.Equal(r.Token.Privileges, []string{changeNotify}) {
			t.Fatalf("privileges %v, want exactly %s", r.Token.Privileges, changeNotify)
		}
	}},
	{name: "default", expect: func(t *testing.T, r selfCheckResult, _ string) {
		if r.Code != CodePrivileges || !strings.Contains(r.Error, "SeImpersonatePrivilege") {
			t.Fatalf("the default privileges: %d %q, want code %d naming SeImpersonatePrivilege", r.Code, r.Error, CodePrivileges)
		}
	}},
	{name: "cut1+administrators", cut: true, group: "admins", expect: func(t *testing.T, r selfCheckResult, _ string) {
		if r.Code != CodeAdministrators {
			t.Fatalf("in Administrators: %d %q, want code %d", r.Code, r.Error, CodeAdministrators)
		}
	}},
	{name: "cut1+group", cut: true, group: "new", expect: func(t *testing.T, r selfCheckResult, groupSID string) {
		if r.Code != CodeExtraGroup || !strings.Contains(r.Error, groupSID) {
			t.Fatalf("in another group: %d %q, want code %d naming %s", r.Code, r.Error, CodeExtraGroup, groupSID)
		}
	}},
}

// TestSelfCheckService runs the self-check in a real service per variant
// (CI only: it registers throwaway services and a group). Its record of
// the token is the measurement of the virtual account's default groups.
func TestSelfCheckService(t *testing.T) {
	if os.Getenv(otherUserEnv) != "1" {
		t.Skipf("set %s=1 to register test services (CI only)", otherUserEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%s=1 needs an elevated (administrator) process", otherUserEnv)
	}
	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	for _, v := range selfCheckVariants {
		t.Run(v.name, func(t *testing.T) { selfCheckOnce(t, m, v) })
	}
}

func selfCheckOnce(t *testing.T, m *mgr.Mgr, v selfCheckVariant) {
	n := "t" + randHex(4)
	name := channel.ServiceName(n)
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
	protectDir(t, dir, "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;"+svcSID.String()+")")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "selfcheck.exe")
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "result.json")
	cfg, _ := json.Marshal(selfCheckConfig{Name: n, Out: out})
	if err := os.WriteFile(filepath.Join(dir, "selfcheck.json"), cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	var groupSID string
	switch v.group {
	case "admins":
		admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		g, _, _, err := admins.LookupAccount("")
		if err != nil {
			t.Fatal(err)
		}
		addToGroup(t, g, svcSID)
		groupSID = admins.String()
	case "new":
		var g string
		g, groupSID = newLocalGroup(t)
		addToGroup(t, g, svcSID)
	}

	s, err := m.CreateService(name, exe, mgr.Config{
		DisplayName:      name,
		StartType:        mgr.StartManual,
		ServiceStartName: `NT SERVICE\` + name,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "-test.run=^TestSelfCheckServiceHelper$")
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	t.Cleanup(func() { removeService(t, m, s, name, svcSID.String()) })
	if v.cut {
		privs := utf16.Encode([]rune(changeNotify + "\x00\x00"))
		rp := struct{ privileges *uint16 }{&privs[0]}
		if err := windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&rp))); err != nil {
			t.Fatalf("required privileges: %v", err)
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v (%d)", err, err)
	}
	var rec []byte
	for end := time.Now().Add(2 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
		if rec, err = os.ReadFile(out); err == nil && len(rec) > 0 {
			break
		}
		if time.Now().After(end) {
			st, _ := s.Query()
			t.Fatalf("no record from the service (state %d, exit %d, service exit %d)", st.State, st.Win32ExitCode, st.ServiceSpecificExitCode)
		}
	}
	t.Logf("%s: service %s (%s)\n%s", v.name, name, svcSID, rec)
	var res selfCheckResult
	if err := json.Unmarshal(rec, &res); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(res.Token.User, svcSID.String()) {
		t.Fatalf("the service ran as %s, not %s", res.Token.User, svcSID)
	}
	v.expect(t, res, groupSID)
}
