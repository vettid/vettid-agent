//go:build windows

package channel

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// otherUserEnv, set to 1 by the Windows CI job's step for these tests,
// lets tests make throwaway local users (as internal/protect's DPAPI
// tests do). They never run on a developer's computer by accident.
const otherUserEnv = "VETTID_AGENT_TEST_OTHER_USER"

// requireElevated skips unless otherUserEnv is 1, and then fails, rather
// than skips, if the process is not an elevated administrator.
func requireElevated(t *testing.T) {
	t.Helper()
	if os.Getenv(otherUserEnv) != "1" {
		t.Skipf("set %s=1 to make test accounts (CI only)", otherUserEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%s=1 needs an elevated (administrator) process", otherUserEnv)
	}
}

var (
	modnetapi32                 = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd              = modnetapi32.NewProc("NetUserAdd")
	procNetUserDel              = modnetapi32.NewProc("NetUserDel")
	procLogonUserW              = windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
	procImpersonateLoggedOnUser = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateLoggedOnUser")
)

type userInfo1 struct {
	name, password *uint16
	passwordAge    uint32
	priv           uint32
	homeDir        *uint16
	comment        *uint16
	flags          uint32
	scriptPath     *uint16
}

// testUser is a throwaway standard local user, logged on (interactive
// logon, profile not loaded); removed when the test ends. Its password
// exists only in this process.
type testUser struct {
	name  string
	sid   *windows.SID
	token windows.Token
}

func newTestUser(t *testing.T) *testUser {
	t.Helper()
	requireElevated(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "vtest" + hex.EncodeToString(b)
	pw := make([]byte, 18)
	_, _ = rand.Read(pw)
	pass := base64.RawURLEncoding.EncodeToString(pw) + "Aa1!"
	n, _ := windows.UTF16PtrFromString(name)
	p, _ := windows.UTF16PtrFromString(pass)
	info := userInfo1{name: n, password: p, priv: 1 /* USER_PRIV_USER */, flags: 0x1 | 0x10000 /* UF_SCRIPT | UF_DONT_EXPIRE_PASSWD */}
	var parm uint32
	if r, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parm))); r != 0 {
		t.Fatalf("NetUserAdd: %d (parameter %d)", r, parm)
	}
	u := &testUser{name: name}
	t.Cleanup(func() {
		if u.token != 0 {
			u.token.Close()
		}
		if r, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(n))); r != 0 {
			t.Errorf("NetUserDel %s: %d", name, r)
		}
	})
	dot, _ := windows.UTF16PtrFromString(".")
	if r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(dot)), uintptr(unsafe.Pointer(p)),
		2 /* LOGON32_LOGON_INTERACTIVE */, 0, uintptr(unsafe.Pointer(&u.token))); r == 0 {
		t.Fatalf("LogonUser: %v", e)
	}
	tu, err := u.token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	u.sid, err = tu.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// as runs f on a thread impersonating u: the pipe is opened, and the
// hello written, as u.
func (u *testUser) as(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread()
		if r, _, e := procImpersonateLoggedOnUser.Call(uintptr(u.token)); r == 0 {
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

// Another user of the computer can't open the pipe at all, nor make an
// instance of it.
func TestOtherUserRefused(t *testing.T) {
	other := newTestUser(t)
	me := selfSID(t)
	s := listen(t, me, "")
	for _, op := range []Op{OpMCP, OpStatus, OpPair} {
		cfg := s.dial(op)
		cfg.Service = me
		var err error
		other.as(t, func() { _, err = Dial(context.Background(), cfg) })
		if !errors.Is(err, ErrAccessDenied) {
			t.Fatalf("%s as another user: %v, want ErrAccessDenied", op, err)
		}
	}
	var err error
	other.as(t, func() {
		p, _ := windows.UTF16PtrFromString(PipePath(s.pipe))
		var h windows.Handle
		h, err = windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE, maxInstances, 4096, 4096, 0, nil)
		if err == nil {
			windows.CloseHandle(h)
		}
	})
	if err == nil {
		t.Fatal("another user made an instance of the pipe")
	}
}

// With the member another account: this test's process, an elevated
// administrator who is not the member, gets status, pair and forget but
// never tools; the member's own normal process gets tools and status,
// never pair or forget, whatever it says.
func TestAdminWhoIsNotTheMember(t *testing.T) {
	member := newTestUser(t)
	me := selfSID(t)
	s := listen(t, member.sid.String(), "")

	// The administrator (this process).
	cfg := s.dial(OpMCP)
	cfg.Service = me
	if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("tools for an administrator who is not the member: %v, want ErrNotAllowed", err)
	}
	for _, op := range []Op{OpStatus, OpPair, OpForget} {
		cfg := s.dial(op)
		cfg.Service = me
		ch := dialAsync(cfg)
		c := s.accepted(t)
		if c.Op != op || !c.Identity.ElevatedAdmin || c.Identity.Member {
			t.Fatalf("%s: server saw %q %+v", op, c.Op, c.Identity)
		}
		_ = c.Accept()
		r := <-ch
		if r.err != nil {
			t.Fatalf("%s for an elevated administrator: %v", op, r.err)
		}
		r.f.Close()
	}

	// The member's normal process. Its dial runs on the impersonating
	// thread, so the server answers from a goroutine of its own.
	seen := make(chan *ServerConn, 4)
	go func() {
		for c := range s.conns {
			_ = c.Accept()
			c.Close()
			seen <- c
		}
	}()
	asMember := func(op Op) error {
		cfg := s.dial(op)
		cfg.Service = me
		var err error
		member.as(t, func() {
			var f *os.File
			f, err = Dial(context.Background(), cfg)
			if f != nil {
				f.Close()
			}
		})
		return err
	}
	for _, op := range []Op{OpMCP, OpStatus} {
		if err := asMember(op); err != nil {
			t.Fatalf("%s for the member: %v", op, err)
		}
		c := <-seen
		if !c.Identity.Member || c.Identity.ElevatedAdmin {
			t.Fatalf("%s: the member seen as %+v", op, c.Identity)
		}
	}
	for _, op := range []Op{OpPair, OpForget} {
		if err := asMember(op); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("%s from the member's normal process: %v, want ErrNotAllowed", op, err)
		}
	}
}

// A pipe made first by another user (a squatter, which grants everyone
// access) stops the service's Listen, and a client expecting the
// service refuses it before sending anything.
func TestSquatterRefused(t *testing.T) {
	other := newTestUser(t)
	me := selfSID(t)
	pipe := randomPipe(t)
	// One instance per client below, each waiting for a client.
	var err error
	other.as(t, func() {
		sd, serr := windows.SecurityDescriptorFromString("D:(A;;0x12019f;;;WD)")
		if serr != nil {
			err = serr
			return
		}
		p, _ := windows.UTF16PtrFromString(PipePath(pipe))
		for i := 0; i < 3 && err == nil; i++ {
			flags := uint32(windows.PIPE_ACCESS_DUPLEX)
			if i == 0 {
				flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
			}
			var h windows.Handle
			h, err = windows.CreateNamedPipe(p, flags, windows.PIPE_TYPE_BYTE, 4, 4096, 4096, 0,
				&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd})
			if err == nil {
				t.Cleanup(func() { windows.CloseHandle(h) })
			}
		}
	})
	if err != nil {
		t.Fatalf("the squatter's pipe: %v", err)
	}
	if _, err := Listen(ListenConfig{Pipe: pipe, Owner: me, Member: me, Version: testVersion}); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("Listen on a squatted name: %v, want ErrNameTaken", err)
	}
	for _, op := range []Op{OpMCP, OpStatus, OpPair} {
		_, err := Dial(context.Background(), DialConfig{Pipe: pipe, Service: me, Op: op, Version: testVersion})
		if !errors.Is(err, ErrNotService) {
			t.Fatalf("%s against a squatter: %v, want ErrNotService", op, err)
		}
	}
}

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

// tokenIdentity counts an administrator as elevated only with the
// Administrators group enabled and integrity at high or above. From this
// (elevated) test's own token: as it is, elevated; at medium integrity,
// not; with Administrators deny-only (as UAC's filtered token has it),
// not.
func TestTokenIdentityElevation(t *testing.T) {
	requireElevated(t)
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	var proc windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &proc); err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	u, err := proc.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := u.User.Sid
	// identification makes an identification-level impersonation token of
	// tok, as the server gets from a client.
	identification := func(tok windows.Token) windows.Token {
		var d windows.Token
		if err := windows.DuplicateTokenEx(tok, windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, nil,
			windows.SecurityIdentification, windows.TokenImpersonation, &d); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		return d
	}

	id, err := tokenIdentity(identification(proc), me, admins)
	if err != nil || !id.ElevatedAdmin || !id.Member {
		t.Fatalf("this elevated token: %+v, %v", id, err)
	}

	medium := identification(proc)
	msid, err := windows.StringToSid("S-1-16-8192")
	if err != nil {
		t.Fatal(err)
	}
	tml := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: msid, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(medium, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&tml)), tml.Size()); err != nil {
		t.Fatal(err)
	}
	if il, err := integrity(medium); err != nil || il != 0x2000 {
		t.Fatalf("medium token's integrity: %#x, %v", il, err)
	}
	if id, err := tokenIdentity(medium, me, admins); err != nil || id.ElevatedAdmin {
		t.Fatalf("Administrators enabled at medium integrity: %+v, %v", id, err)
	}

	var restricted windows.Token
	disable := windows.SIDAndAttributes{Sid: admins}
	if r, _, e := procCreateRestrictedToken.Call(uintptr(proc), 0, 1, uintptr(unsafe.Pointer(&disable)), 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&restricted))); r == 0 {
		t.Fatalf("CreateRestrictedToken: %v", e)
	}
	defer restricted.Close()
	denyOnly := identification(restricted)
	if il, err := integrity(denyOnly); err != nil || il < integrityHigh {
		t.Fatalf("the restricted token's integrity: %#x, %v (it should stay high)", il, err)
	}
	if id, err := tokenIdentity(denyOnly, me, admins); err != nil || id.ElevatedAdmin {
		t.Fatalf("Administrators deny-only at high integrity: %+v, %v", id, err)
	}
}
