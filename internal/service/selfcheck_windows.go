//go:build windows

package service

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vettid/vettid-agent/internal/channel"
)

var procLookupPrivilegeName = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")

// The only privilege the service's token may hold (AGENT-SEPARATE-ACCOUNT
// §3, "Windows privileges"): the installer cuts the required-privileges
// list to it, with no LSA grant.
const changeNotify = "SeChangeNotifyPrivilege"

// Why the self-check refused, as the service's exit code
// (ServiceSpecificExitCode): the stub's `status` reads it from the
// service manager (chosen; not in the spec).
const (
	CodeTokenUnreadable uint32 = 101 // the token could not be read
	CodeWrongAccount    uint32 = 102 // not NT SERVICE\vettid-agent-<n>
	CodePrivileges      uint32 = 103 // a privilege beyond SeChangeNotifyPrivilege
	CodeAdministrators  uint32 = 104 // in Administrators, in any form
	CodeExtraGroup      uint32 = 105 // a group beyond the virtual account's defaults
)

// CheckError is the self-check's refusal: a code (above) and what it saw.
type CheckError struct {
	Code   uint32
	Detail string
}

func (e *CheckError) Error() string { return e.Detail }

// Group is one of a token's groups: its SID in string form and its
// attributes (SE_GROUP_*).
type Group struct {
	SID        string
	Attributes uint32
}

// Token is what the self-check reads from a token.
type Token struct {
	User       string
	Privileges []string // names, enabled or not
	Groups     []Group
}

// ReadToken reads tok's user, privileges and groups.
func ReadToken(tok windows.Token) (Token, error) {
	var t Token
	u, err := tok.GetTokenUser()
	if err != nil {
		return t, fmt.Errorf("the token's user: %w", err)
	}
	t.User = u.User.Sid.String()
	t.Privileges, err = privileges(tok)
	if err != nil {
		return t, fmt.Errorf("the token's privileges: %w", err)
	}
	g, err := tok.GetTokenGroups()
	if err != nil {
		return t, fmt.Errorf("the token's groups: %w", err)
	}
	for _, a := range g.AllGroups() {
		t.Groups = append(t.Groups, Group{SID: a.Sid.String(), Attributes: a.Attributes})
	}
	return t, nil
}

// privileges are the names of the privileges tok holds, enabled or not.
func privileges(tok windows.Token) ([]string, error) {
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &n)
	if n < 4 {
		return nil, errors.New("no privilege list")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], n, &n); err != nil {
		return nil, err
	}
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	var names []string
	for _, p := range tp.AllPrivileges() {
		name := make([]uint16, 128)
		l := uint32(len(name))
		if r, _, e := procLookupPrivilegeName.Call(0, uintptr(unsafe.Pointer(&p.Luid)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&l))); r == 0 {
			return nil, fmt.Errorf("a privilege's name: %w", e)
		}
		names = append(names, windows.UTF16ToString(name[:l]))
	}
	return names, nil
}

// SelfCheck reads this process's token and checks it as pairing n's
// service: Check.
func SelfCheck(n string) (Token, error) {
	t, err := ReadToken(windows.GetCurrentProcessToken())
	if err != nil {
		return t, &CheckError{Code: CodeTokenUnreadable, Detail: err.Error()}
	}
	return t, Check(t, channel.ServiceSID(channel.ServiceName(n)))
}

// seGroupIntegrity marks a token's mandatory label among its groups.
const seGroupIntegrity = 0x20

// defaultGroups are the groups a virtual service account's token holds
// besides its logon SID and its integrity label: measured on
// windows-2025 by this package's service test (TestSelfCheckService,
// privileges cut to SeChangeNotifyPrivilege, SidType unrestricted),
// which read exactly these, a logon SID and the label S-1-16-12288
// (High). The self-check's list (AGENT-SEPARATE-ACCOUNT §3).
var defaultGroups = map[string]string{
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "LOCAL",
	"S-1-2-1":      "CONSOLE LOGON",
	"S-1-5-6":      "SERVICE",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-15":     "This Organization",
	"S-1-5-32-545": "Users",
	"S-1-5-80-0":   "NT SERVICE\\ALL SERVICES",
}

// Check refuses a token that is not the service's own (serviceSID), that
// holds any privilege but SeChangeNotifyPrivilege, that holds
// Administrators in any form (enabled or deny-only), or that holds any
// group beyond defaultGroups, the service's own SID, a logon SID
// (S-1-5-5-x-y) and its integrity label. Every privilege and group is
// checked, so a Windows build that adds one fails closed.
func Check(t Token, serviceSID string) error {
	if !strings.EqualFold(t.User, serviceSID) {
		return &CheckError{Code: CodeWrongAccount, Detail: fmt.Sprintf("the service runs as %s, not as its own account %s", t.User, serviceSID)}
	}
	var extra []string
	for _, p := range t.Privileges {
		if p != changeNotify {
			extra = append(extra, p)
		}
	}
	if len(extra) > 0 {
		return &CheckError{Code: CodePrivileges, Detail: "the service holds privileges beyond " + changeNotify + ": " + strings.Join(extra, ", ")}
	}
	var groups []string
	for _, g := range t.Groups {
		switch {
		case g.SID == "S-1-5-32-544":
			return &CheckError{Code: CodeAdministrators, Detail: "the service's account is in Administrators"}
		case strings.EqualFold(g.SID, serviceSID), defaultGroups[g.SID] != "", isLogonSID(g.SID):
		case g.Attributes&seGroupIntegrity != 0 && strings.HasPrefix(g.SID, "S-1-16-"):
		default:
			groups = append(groups, g.SID)
		}
	}
	if len(groups) > 0 {
		return &CheckError{Code: CodeExtraGroup, Detail: "the service's account is in groups beyond its defaults: " + strings.Join(groups, ", ")}
	}
	return nil
}

// isLogonSID: S-1-5-5-x-y, a logon session's SID.
func isLogonSID(s string) bool {
	rest, ok := strings.CutPrefix(s, "S-1-5-5-")
	if !ok {
		return false
	}
	a, b, ok := strings.Cut(rest, "-")
	return ok && digits(a) && digits(b)
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
