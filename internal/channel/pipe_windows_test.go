//go:build windows

package channel

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const testVersion = "v0.0.0-test"

func selfSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

func randomPipe(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "vettid-agent-test-" + hex.EncodeToString(b)
}

// refusals collects what a listener refused.
type refusals struct {
	mu  sync.Mutex
	got []error
}

func (r *refusals) add(_ Op, err error) {
	r.mu.Lock()
	r.got = append(r.got, err)
	r.mu.Unlock()
}

func (r *refusals) wait(t *testing.T, n int) []error {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		r.mu.Lock()
		if len(r.got) >= n {
			got := append([]error(nil), r.got...)
			r.mu.Unlock()
			return got
		}
		r.mu.Unlock()
	}
	t.Fatalf("the listener refused fewer than %d clients", n)
	return nil
}

// server is a listener owned by this test's own user, for the member
// given, accepting in the background.
type server struct {
	l       *Listener
	pipe    string
	conns   chan *ServerConn
	refused *refusals
}

func listen(t *testing.T, member, extra string) *server {
	t.Helper()
	s := &server{pipe: randomPipe(t), conns: make(chan *ServerConn, 4), refused: &refusals{}}
	l, err := Listen(ListenConfig{Pipe: s.pipe, Owner: selfSID(t), Member: member, Version: testVersion,
		OnRefused: s.refused.add, extraSDDL: extra})
	if err != nil {
		t.Fatal(err)
	}
	s.l = l
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			s.conns <- c
		}
	}()
	t.Cleanup(func() {
		cancel()
		l.Close()
		<-done
	})
	return s
}

func (s *server) dial(op Op) DialConfig {
	return DialConfig{Pipe: s.pipe, Op: op, Version: testVersion}
}

func (s *server) accepted(t *testing.T) *ServerConn {
	t.Helper()
	select {
	case c := <-s.conns:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no client accepted")
		return nil
	}
}

// dialAsync dials while the test answers on the server's side.
func dialAsync(cfg DialConfig) <-chan dialResult {
	ch := make(chan dialResult, 1)
	go func() {
		f, err := Dial(context.Background(), cfg)
		ch <- dialResult{f, err}
	}()
	return ch
}

type dialResult struct {
	f   io.ReadWriteCloser
	err error
}

func TestServiceSIDMatchesWindows(t *testing.T) {
	for _, name := range []string{"TrustedInstaller", "EventLog", "Schedule"} {
		sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := ServiceSID(name); got != sid.String() {
			t.Errorf("ServiceSID(%s) = %s, Windows says %s", name, got, sid)
		}
	}
}

// The member's client is admitted for tools, and bytes pass unchanged
// both ways after the hellos.
func TestPipeRoundTrip(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	cfg := s.dial(memberOp(t))
	cfg.Service = me
	ch := dialAsync(cfg)
	c := s.accepted(t)
	if c.Op != memberOp(t) || !c.Identity.Member {
		t.Fatalf("server saw op %q identity %+v", c.Op, c.Identity)
	}
	if err := c.Accept(); err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	defer r.f.Close()
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	if _, err := io.WriteString(r.f, msg); err != nil {
		t.Fatal(err)
	}
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || got != msg {
		t.Fatalf("server read %q, %v", got, err)
	}
	ans := `{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"
	if _, err := io.WriteString(c, ans); err != nil {
		t.Fatal(err)
	}
	got, err = bufio.NewReader(r.f).ReadString('\n')
	if err != nil || got != ans {
		t.Fatalf("client read %q, %v", got, err)
	}
}

// A second stub on the pairing is refused with ErrInUse (the service's
// call, A3.10b), which the client reports as such.
func TestPipeInUse(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	cfg := s.dial(memberOp(t))
	cfg.Service = me
	ch := dialAsync(cfg)
	if err := s.accepted(t).Refuse(ErrInUse); err != nil {
		t.Fatal(err)
	}
	if r := <-ch; !errors.Is(r.err, ErrInUse) {
		t.Fatalf("Dial = %v, want ErrInUse", r.err)
	}
}

// A server that isn't owned by the service's SID (here: a pipe of this
// test's user, while the client expects the service's) is refused before
// anything is sent: the server reads no hello.
func TestPipeOwnerChecked(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	cfg := s.dial(OpMCP)
	cfg.Service = ServiceSID(ServiceName("test"))
	if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrNotService) {
		t.Fatalf("Dial = %v, want ErrNotService", err)
	}
	// No hello reached the server: it saw the client leave, either before
	// its connect completed (ERROR_NO_DATA) or before a whole hello line.
	got := s.refused.wait(t, 1)
	if !errors.Is(got[0], ErrBadHello) && !errors.Is(got[0], windows.ERROR_NO_DATA) {
		t.Fatalf("the server got %v, want no hello at all", got[0])
	}
}

func TestPipeNoService(t *testing.T) {
	_, err := Dial(context.Background(), DialConfig{Pipe: randomPipe(t), Service: selfSID(t), Op: OpMCP, Version: testVersion})
	if !errors.Is(err, ErrNoService) {
		t.Fatalf("Dial = %v, want ErrNoService", err)
	}
}

// A name already taken stops a second Listen (FILE_FLAG_FIRST_PIPE_INSTANCE).
func TestPipeNameTaken(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	_, err := Listen(ListenConfig{Pipe: s.pipe, Owner: me, Member: me, Version: testVersion})
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("second Listen = %v, want ErrNameTaken", err)
	}
}

func TestPipeVersionsDiffer(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	cfg := s.dial(OpMCP)
	cfg.Service = me
	cfg.Version = "v9.9.9"
	if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrVersionsDiffer) {
		t.Fatalf("Dial = %v, want ErrVersionsDiffer", err)
	}
	if got := s.refused.wait(t, 1); !errors.Is(got[0], ErrVersionsDiffer) {
		t.Fatalf("server refused with %v", got[0])
	}
}

// A client that lets the server see it only anonymously is refused.
func TestPipeAnonymousRefused(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	cfg := s.dial(OpMCP)
	cfg.Service = me
	cfg.anonymous = true
	if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("Dial = %v, want ErrNotAllowed", err)
	}
	got := s.refused.wait(t, 1)
	t.Logf("server: %v", got[0])
}

// pair and forget are refused to a client that is not an elevated
// administrator; status is the member's too.
func TestPipeOpsByToken(t *testing.T) {
	me := selfSID(t)
	elevated := windows.GetCurrentProcessToken().IsElevated()
	s := listen(t, me, "")
	for _, op := range []Op{OpStatus, OpPair, OpForget} {
		cfg := s.dial(op)
		cfg.Service = me
		ch := dialAsync(cfg)
		want := op == OpStatus || elevated
		if !want {
			if r := <-ch; !errors.Is(r.err, ErrNotAllowed) {
				t.Fatalf("%s: Dial = %v, want ErrNotAllowed", op, r.err)
			}
			continue
		}
		c := s.accepted(t)
		if c.Op != op {
			t.Fatalf("server saw %q", c.Op)
		}
		_ = c.Accept()
		if r := <-ch; r.err != nil {
			t.Fatalf("%s: %v", op, r.err)
		} else {
			r.f.Close()
		}
	}
}

// What the pipe's access list holds, read back through a handle: the
// member and Administrators get exactly 0x120083, only the owner may
// create instances, NETWORK is denied.
func TestPipeAccessList(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	p, _ := windows.UTF16PtrFromString(PipePath(s.pipe))
	h, err := windows.CreateFile(p, windows.READ_CONTROL, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	got := sd.String()
	// Written out, then put in Windows' own form (which abbreviates some
	// accounts, such as the built-in Administrator as LA).
	wantSD, err := windows.SecurityDescriptorFromString("O:" + me + "D:P(D;;FA;;;NU)(A;;FA;;;" + me + ")(A;;0x120083;;;" + me + ")(A;;0x120083;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	if want := wantSD.String(); got != want {
		t.Fatalf("pipe security\n got %s\nwant %s", got, want)
	}
	if clientMask != 0x120083 {
		t.Fatalf("clientMask = %#x", clientMask)
	}
}

// GENERIC_WRITE holds FILE_APPEND_DATA, the right to create an instance:
// a client asking for it is refused at open.
func TestPipeGenericWriteRefused(t *testing.T) {
	// The listener's owner holds every right, so the check is made on a
	// pipe whose access list gives this test's user the member's entry
	// alone.
	me := selfSID(t)
	pipe := randomPipe(t)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;0x120083;;;" + me + ")")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(PipePath(pipe))
	h, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 2, 4096, 4096, 0,
		&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd})
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	c, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		if err == nil {
			windows.CloseHandle(c)
		}
		t.Fatalf("GENERIC_WRITE open = %v, want access denied", err)
	}
	c, err = windows.CreateFile(p, clientAccess, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatalf("the client's own access = %v", err)
	}
	windows.CloseHandle(c)
	// And with 0x120083 alone, no second instance can be made.
	h2, err := windows.CreateNamedPipe(p, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE, 2, 4096, 4096, 0, nil)
	if err == nil {
		windows.CloseHandle(h2)
		t.Fatal("an account with the member's rights made an instance")
	}
}

// A client through the computer's name (as from the network) is
// refused: PIPE_REJECT_REMOTE_CLIENTS and NETWORK denied.
func TestPipeRemoteRefused(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	cfg := s.dial(OpMCP)
	cfg.Service = me
	cfg.server = "localhost"
	cfg.Wait = time.Second
	_, err := Dial(context.Background(), cfg)
	if err == nil {
		t.Fatal("a client through \\\\localhost was admitted")
	}
	if errors.Is(err, windows.ERROR_BAD_NETPATH) || strings.Contains(err.Error(), "network path was not found") {
		t.Skipf("no file sharing on this computer: %v", err)
	}
	// Refused at open (the flag), not later by the service: a member who
	// is an administrator would be refused tools anyway.
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("remote client: %v, want ErrAccessDenied", err)
	}
	t.Logf("remote client: %v", err)
	select {
	case c := <-s.conns:
		c.Close()
		t.Fatal("the server accepted a remote client")
	default:
	}
}

func TestListenerCloseEndsAccept(t *testing.T) {
	me := selfSID(t)
	l, err := Listen(ListenConfig{Pipe: randomPipe(t), Owner: me, Member: me, Version: testVersion})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept(context.Background())
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	l.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept returned a client")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end Accept")
	}
}

// A client that opens and closes before the server's connect fails the
// waiting instance (ERROR_NO_DATA). Its replacement exists before it is
// closed: at that moment nobody else can take the name.
func TestPipeFailedInstanceKeepsName(t *testing.T) {
	me := selfSID(t)
	pipe := randomPipe(t)
	l, err := Listen(ListenConfig{Pipe: pipe, Owner: me, Member: me, Version: testVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var takenErr error
	replaced := make(chan struct{})
	// afterReplace runs right after the failed instance is closed. A
	// regression that closes it before making the replacement fails this
	// test only if the hook stays next to the close: keep them together.
	l.afterReplace = func() {
		_, takenErr = Listen(ListenConfig{Pipe: pipe, Owner: me, Member: me, Version: testVersion})
		close(replaced)
	}
	// Open and close before Accept connects.
	p, _ := windows.UTF16PtrFromString(PipePath(pipe))
	h, err := windows.CreateFile(p, clientAccess, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		t.Fatal(err)
	}
	windows.CloseHandle(h)
	refused := &refusals{}
	l.cfg.OnRefused = refused.add
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan *ServerConn, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err == nil {
			accepted <- c
		}
	}()
	select {
	case <-replaced:
	case <-time.After(5 * time.Second):
		t.Fatal("the failed instance was not replaced")
	}
	if !errors.Is(takenErr, ErrNameTaken) {
		t.Fatalf("while replacing, another Listen got %v: the name was free", takenErr)
	}
	// And the listener goes on: a client is served.
	ch := dialAsync(DialConfig{Pipe: pipe, Service: me, Op: memberOp(t), Version: testVersion})
	select {
	case c := <-accepted:
		_ = c.Accept()
		defer c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no client accepted after the failed instance")
	}
	if r := <-ch; r.err != nil {
		t.Fatal(r.err)
	} else {
		r.f.Close()
	}
}

// Beyond maxConns clients at once, the next is told the channel is busy,
// and the listener goes on: once one closes, a client is served again.
func TestPipeBusy(t *testing.T) {
	me := selfSID(t)
	s := listenN(t, me, maxConns+2)
	var clients []io.Closer
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	var held []*ServerConn
	for i := 0; i < maxConns; i++ {
		cfg := s.dial(memberOp(t))
		cfg.Service = me
		ch := dialAsync(cfg)
		c := s.accepted(t)
		_ = c.Accept()
		held = append(held, c)
		r := <-ch
		if r.err != nil {
			t.Fatalf("client %d: %v", i, r.err)
		}
		clients = append(clients, r.f)
	}
	cfg := s.dial(memberOp(t))
	cfg.Service = me
	if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrBusy) {
		t.Fatalf("client %d: %v, want ErrBusy", maxConns+1, err)
	}
	held[0].Close()
	ch := dialAsync(cfg)
	c := s.accepted(t)
	_ = c.Accept()
	if r := <-ch; r.err != nil {
		t.Fatalf("after one closed: %v", r.err)
	} else {
		r.f.Close()
	}
}

// Without the NETWORK deny, PIPE_REJECT_REMOTE_CLIENTS alone still
// refuses a client through the computer's name: the flag is tested on
// its own, not only through the access list.
func TestPipeRejectRemoteFlag(t *testing.T) {
	me := selfSID(t)
	s := &server{pipe: randomPipe(t), conns: make(chan *ServerConn, 4), refused: &refusals{}}
	l, err := Listen(ListenConfig{Pipe: s.pipe, Owner: me, Member: me, Version: testVersion, OnRefused: s.refused.add,
		noNetworkDeny: true, extraSDDL: "(A;;0x120083;;;NU)"})
	if err != nil {
		t.Fatal(err)
	}
	s.l = l
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			s.conns <- c
		}
	}()
	cfg := s.dial(OpMCP)
	cfg.Service = me
	cfg.server = "localhost"
	cfg.Wait = time.Second
	_, err = Dial(context.Background(), cfg)
	if err == nil {
		t.Fatal("a client through \\localhost was admitted")
	}
	if errors.Is(err, windows.ERROR_BAD_NETPATH) || strings.Contains(err.Error(), "network path was not found") {
		t.Skipf("no file sharing on this computer: %v", err)
	}
	// Refused at open (the flag), not later by the service: a member who
	// is an administrator would be refused tools anyway.
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("remote client: %v, want ErrAccessDenied", err)
	}
	t.Logf("remote client, the flag alone: %v", err)
	select {
	case c := <-s.conns:
		c.Close()
		t.Fatal("the server accepted a remote client")
	default:
	}
}

// listenN is listen with room for n waiting connections.
func listenN(t *testing.T, member string, n int) *server {
	t.Helper()
	s := &server{pipe: randomPipe(t), conns: make(chan *ServerConn, n), refused: &refusals{}}
	l, err := Listen(ListenConfig{Pipe: s.pipe, Owner: selfSID(t), Member: member, Version: testVersion, OnRefused: s.refused.add})
	if err != nil {
		t.Fatal(err)
	}
	s.l = l
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			s.conns <- c
		}
	}()
	t.Cleanup(func() {
		cancel()
		l.Close()
		<-done
	})
	return s
}

// Close while no Accept waits closes the waiting instance; a later
// Accept says the channel is closed.
func TestListenerCloseIdle(t *testing.T) {
	me := selfSID(t)
	pipe := randomPipe(t)
	l, err := Listen(ListenConfig{Pipe: pipe, Owner: me, Member: me, Version: testVersion})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Accept(context.Background()); !errors.Is(err, errClosed) {
		t.Fatalf("Accept after Close: %v", err)
	}
	if _, err := Dial(context.Background(), DialConfig{Pipe: pipe, Service: me, Op: OpMCP, Version: testVersion}); !errors.Is(err, ErrNoService) {
		t.Fatalf("Dial after Close: %v, want ErrNoService", err)
	}
}

// selfHoldsAdmins: this test's token holds Administrators (the CI
// runner's does; a standard user's doesn't).
func selfHoldsAdmins(t *testing.T) bool {
	t.Helper()
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	holds, err := holdsGroup(windows.GetCurrentProcessToken(), admins)
	if err != nil {
		t.Fatal(err)
	}
	return holds
}

// memberOp is an operation the service admits for this test's account
// as the member: tools, unless the account is an administrator
// (TestPipeMemberIsAdmin); status always.
func memberOp(t *testing.T) Op {
	if selfHoldsAdmins(t) {
		return OpStatus
	}
	return OpMCP
}

// A member whose token holds Administrators gets no tools, with its own
// refusal (member_is_admin), but still gets status; a standard member
// gets tools.
func TestPipeMemberIsAdmin(t *testing.T) {
	me := selfSID(t)
	s := listen(t, me, "")
	cfg := s.dial(OpMCP)
	cfg.Service = me
	if selfHoldsAdmins(t) {
		if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrMemberIsAdmin) {
			t.Fatalf("tools for an administrator member: %v, want ErrMemberIsAdmin", err)
		}
		if got := s.refused.wait(t, 1); !errors.Is(got[0], ErrMemberIsAdmin) {
			t.Fatalf("server refused with %v", got[0])
		}
		cfg.Op = OpStatus
	}
	ch := dialAsync(cfg)
	c := s.accepted(t)
	if !c.Identity.Member || c.Identity.HoldsAdmins != selfHoldsAdmins(t) {
		t.Fatalf("server saw %+v", c.Identity)
	}
	_ = c.Accept()
	if r := <-ch; r.err != nil {
		t.Fatalf("%s for the member: %v", cfg.Op, r.err)
	} else {
		r.f.Close()
	}
}
