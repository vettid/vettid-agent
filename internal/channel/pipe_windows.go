//go:build windows

package channel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")
	procWaitNamedPipeW             = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")
)

const (
	// clientAccess is what every client asks for: read and write of data,
	// and READ_CONTROL for the owner check. Never GENERIC_WRITE, which
	// holds FILE_APPEND_DATA, the right to create an instance.
	clientAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.READ_CONTROL
	// clientMask is what the member's and the Administrators' entries
	// grant: clientAccess and the two rights CreateFileW adds to every
	// open (SYNCHRONIZE, FILE_READ_ATTRIBUTES), 0x120083. Not
	// FILE_APPEND_DATA (FILE_CREATE_PIPE_INSTANCE), FILE_WRITE_ATTRIBUTES,
	// WRITE_DAC or WRITE_OWNER.
	clientMask = clientAccess | windows.SYNCHRONIZE | windows.FILE_READ_ATTRIBUTES

	// maxInstances: the pipe allows as many instances as Windows does,
	// so that making the next one never fails for want of room; the
	// clients served at once are bounded by maxConns instead.
	maxInstances = windows.PIPE_UNLIMITED_INSTANCES
	// maxConns bounds the clients connected at once; one beyond it is
	// told the channel is busy (chosen; not in the spec).
	maxConns = 16
	bufSize  = 64 << 10

	// helloWait bounds each end's hello (chosen; not in the spec).
	helloWait = 10 * time.Second

	tokenIsAppContainer = 29 // TOKEN_INFORMATION_CLASS TokenIsAppContainer
	integrityHigh       = 0x3000
)

// ServiceAccount is the account that must own pairing n's channel, as
// the client checks it: the SID of the virtual service account
// NT SERVICE\vettid-agent-<n>.
func ServiceAccount(n string) string { return ServiceSID(ServiceName(n)) }

// PipePath is the full path of the pipe named pipe.
func PipePath(pipe string) string { return `\\.\pipe\` + pipe }

// pipeSDDL is the pipe's security descriptor: owned by the service,
// which alone may create instances; the member and the Administrators
// group may read and write data and read the owner; NETWORK is denied.
// An administrator whose token is not elevated holds Administrators as a
// deny-only group, so that entry admits only an elevated one. extra
// adds entries (tests only).
func pipeSDDL(owner, member, extra string) string {
	return fmt.Sprintf("O:%sD:P(D;;GA;;;NU)(A;;GA;;;%s)(A;;0x%x;;;%s)(A;;0x%x;;;BA)%s",
		owner, owner, clientMask, member, clientMask, extra)
}

// ListenConfig configures Listen.
type ListenConfig struct {
	// Pipe is the pipe's name, without \\.\pipe\.
	Pipe string
	// Owner is the service's SID (the account the server runs as), the
	// pipe's owner. Member is the member's SID.
	Owner, Member string
	// Version is this program's version; a client of another version is
	// refused.
	Version string
	// OnRefused, if set, is told of each client refused before Accept
	// returns it (its operation if it named one, and why). It must not
	// block.
	OnRefused func(op Op, err error)

	extraSDDL     string // tests only: more access entries
	noNetworkDeny bool   // tests only: leave out the NETWORK deny, to test PIPE_REJECT_REMOTE_CLIENTS alone
}

// Listener is the server end: the service's. Accept is called from one
// goroutine at a time.
type Listener struct {
	cfg    ListenConfig
	path   *uint16
	sa     *windows.SecurityAttributes
	member *windows.SID
	admins *windows.SID

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.Mutex
	// next is the instance waiting for a client. While Accept waits on it
	// (waiting), Accept alone may close it; otherwise Close does. There is
	// always one while the listener is open, so the pipe's name is never
	// free.
	next    windows.Handle
	waiting bool
	closed  bool
	broken  error
	live    int // clients connected and not yet closed (maxConns)

	afterReplace func() // tests only: runs once a failed instance is closed
}

// errClosed: the listener was closed.
var errClosed = errors.New("the channel is closed")

// Listen creates the pipe with FILE_FLAG_FIRST_PIPE_INSTANCE: if its
// name is taken (another account made it first), it returns
// ErrNameTaken and the service must not start.
func Listen(cfg ListenConfig) (*Listener, error) {
	member, err := windows.StringToSid(cfg.Member)
	if err != nil {
		return nil, fmt.Errorf("the member's SID: %w", err)
	}
	if _, err := windows.StringToSid(cfg.Owner); err != nil {
		return nil, fmt.Errorf("the service's SID: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	sddl := pipeSDDL(cfg.Owner, cfg.Member, cfg.extraSDDL)
	if cfg.noNetworkDeny {
		sddl = strings.Replace(sddl, "(D;;GA;;;NU)", "", 1)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("the pipe's access: %w", err)
	}
	path, err := windows.UTF16PtrFromString(PipePath(cfg.Pipe))
	if err != nil {
		return nil, err
	}
	l := &Listener{cfg: cfg, path: path, member: member, admins: admins,
		sa: &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}}
	h, err := l.instance(true)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("%w (%v)", ErrNameTaken, err)
		}
		return nil, err
	}
	l.next = h
	l.ctx, l.cancel = context.WithCancel(context.Background())
	return l, nil
}

func (l *Listener) instance(first bool) (windows.Handle, error) {
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	return windows.CreateNamedPipe(l.path, flags, mode, maxInstances, bufSize, bufSize, 0, l.sa)
}

// Close stops Accept and closes the waiting instance (or has Accept
// close it, if it is waiting on it). Connections already accepted stay
// open.
func (l *Listener) Close() error {
	l.cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.next != 0 && !l.waiting {
		h := l.next
		l.next = 0
		return windows.CloseHandle(h)
	}
	return nil
}

// ServerConn is an admitted client, waiting for the service's answer:
// Accept (the operation's bytes follow) or Refuse. Close it with
// ServerConn.Close (or Refuse), never through the embedded File: only
// ServerConn.Close gives its place back to the maxConns count, and a
// connection closed otherwise keeps it for good.
type ServerConn struct {
	*os.File
	Op       Op
	Identity Identity
	version  string
	l        *Listener
	once     sync.Once
}

// Accept answers the client's hello: the operation may start.
func (c *ServerConn) Accept() error { return accept(c.File, c.version) }

// Refuse answers the client's hello with a refusal (ErrInUse, for a
// second stub on the pairing) and closes the connection.
func (c *ServerConn) Refuse(err error) error {
	rerr := refuse(c.File, c.version, err)
	cerr := c.Close()
	return errors.Join(rerr, cerr)
}

// Close closes the connection, which then no longer counts toward
// maxConns.
func (c *ServerConn) Close() error {
	err := c.File.Close()
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.live--
		c.l.mu.Unlock()
	})
	return err
}

// Accept waits for a client that names an operation it may run, from a
// token the pipe can identify (Admit). Clients refused on the way are
// told so and reported to OnRefused; Accept returns only an admitted
// client, or an error once ctx ends, the listener is closed, or the pipe
// can't go on (then the service should stop).
func (l *Listener) Accept(ctx context.Context) (*ServerConn, error) {
	for {
		c, err := l.acceptOne(ctx)
		if err == nil {
			return c, nil
		}
		var ce *clientError
		if !errors.As(err, &ce) {
			return nil, err
		}
		if l.cfg.OnRefused != nil {
			l.cfg.OnRefused(ce.op, ce.err)
		}
	}
}

// clientError is one client's failure; Accept goes on to the next.
type clientError struct {
	op  Op
	err error
}

func (e *clientError) Error() string { return e.err.Error() }

func (l *Listener) acceptOne(ctx context.Context) (*ServerConn, error) {
	l.mu.Lock()
	switch {
	case l.closed:
		l.mu.Unlock()
		return nil, errClosed
	case l.broken != nil:
		l.mu.Unlock()
		return nil, l.broken
	case l.waiting:
		l.mu.Unlock()
		return nil, errors.New("the channel is already waiting for a client")
	}
	h := l.next
	l.waiting = true
	l.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(l.ctx, cancel)
	defer stop()
	cerr := connect(ctx, h)

	l.mu.Lock()
	l.waiting = false
	if l.closed {
		l.next = 0
		l.mu.Unlock()
		windows.CloseHandle(h)
		return nil, errClosed
	}
	if cerr != nil && ctx.Err() != nil {
		// Cancelled: h stays the waiting instance.
		l.mu.Unlock()
		return nil, ctx.Err()
	}
	// h is connected, or failed (a client that came and left before the
	// connection, ERROR_NO_DATA): either way it is replaced. The next
	// instance is made before h is handed out or closed, so the pipe's
	// name is never free while the service runs.
	nh, ierr := l.instance(false)
	if ierr != nil {
		// h still holds the name; the service must stop.
		l.broken = fmt.Errorf("the channel can't make a new instance: %w", ierr)
		if cerr != nil {
			l.mu.Unlock()
			return nil, l.broken
		}
		l.next = 0
	} else {
		l.next = nh
	}
	if cerr != nil {
		l.mu.Unlock()
		windows.CloseHandle(h)
		if l.afterReplace != nil {
			l.afterReplace()
		}
		return nil, &clientError{err: cerr}
	}
	l.live++
	busy := l.live > maxConns
	broken := l.broken
	l.mu.Unlock()

	c := &ServerConn{File: os.NewFile(uintptr(h), PipePath(l.cfg.Pipe)), version: l.cfg.Version, l: l}
	if broken != nil {
		c.Close()
		return nil, broken
	}
	_ = c.SetDeadline(time.Now().Add(helloWait))
	op, err := readClientHello(c.File, l.cfg.Version)
	if err != nil {
		c.Close()
		return nil, &clientError{op: op, err: err}
	}
	if busy {
		_ = refuse(c.File, l.cfg.Version, ErrBusy)
		c.Close()
		return nil, &clientError{op: op, err: ErrBusy}
	}
	id, err := identify(h, l.member, l.admins)
	if err == nil {
		err = Admit(op, id)
	}
	if err != nil {
		// The client learns only not_allowed, or member_is_admin.
		why := ErrNotAllowed
		if errors.Is(err, ErrMemberIsAdmin) {
			why = ErrMemberIsAdmin
		}
		_ = refuse(c.File, l.cfg.Version, why)
		c.Close()
		return nil, &clientError{op: op, err: err}
	}
	_ = c.SetDeadline(time.Time{})
	c.Op, c.Identity = op, id
	return c, nil
}

// connect waits for a client on instance h until ctx ends.
func connect(ctx context.Context, h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	ov := &windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(err, windows.ERROR_IO_PENDING):
		return err
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			_ = windows.CancelIoEx(h, ov)
		case <-done:
		}
	}()
	var n uint32
	err = windows.GetOverlappedResult(h, ov, &n, true)
	close(done)
	wg.Wait()
	return err
}

// identify reads the client of h from its token, at the level the
// client allowed (identification): never from its process id. A client
// that allowed only anonymous, and an AppContainer client, are refused.
// It runs on a thread of its own, which ends if the thread can't stop
// impersonating.
func identify(h windows.Handle, member, admins *windows.SID) (Identity, error) {
	type result struct {
		id  Identity
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h))
		if r == 0 {
			runtime.UnlockOSThread()
			ch <- result{err: fmt.Errorf("the client can't be identified: %w", e)}
			return
		}
		var tok windows.Token
		oerr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
		if err := windows.RevertToSelf(); err != nil {
			// The thread stays locked and ends with this goroutine.
			if oerr == nil {
				tok.Close()
			}
			ch <- result{err: fmt.Errorf("the client can't be identified: %w", err)}
			return
		}
		runtime.UnlockOSThread()
		if oerr != nil {
			ch <- result{err: fmt.Errorf("the client can't be identified: %w", oerr)}
			return
		}
		defer tok.Close()
		id, err := tokenIdentity(tok, member, admins)
		ch <- result{id, err}
	}()
	r := <-ch
	return r.id, r.err
}

// tokenIdentity reads an impersonation token of a client.
func tokenIdentity(tok windows.Token, member, admins *windows.SID) (Identity, error) {
	level, err := tokenUint32(tok, windows.TokenImpersonationLevel)
	if err != nil {
		return Identity{}, fmt.Errorf("the client's token: %w", err)
	}
	if level < windows.SecurityIdentification {
		return Identity{}, errors.New("the client is anonymous")
	}
	ac, err := tokenUint32(tok, tokenIsAppContainer)
	if err != nil {
		return Identity{}, fmt.Errorf("the client's token: %w", err)
	}
	if ac != 0 {
		return Identity{}, errors.New("the client runs in an AppContainer")
	}
	user, err := tok.GetTokenUser()
	if err != nil {
		return Identity{}, fmt.Errorf("the client's token: %w", err)
	}
	if user.User.Sid.IsWellKnown(windows.WinAnonymousSid) {
		return Identity{}, errors.New("the client is anonymous")
	}
	id := Identity{Member: windows.EqualSid(user.User.Sid, member)}
	holds, err := holdsGroup(tok, admins)
	if err != nil {
		return Identity{}, fmt.Errorf("the client's token: %w", err)
	}
	id.HoldsAdmins = holds
	admin, err := tok.IsMember(admins)
	if err != nil {
		return Identity{}, fmt.Errorf("the client's token: %w", err)
	}
	if admin {
		il, err := integrity(tok)
		if err != nil {
			return Identity{}, fmt.Errorf("the client's token: %w", err)
		}
		id.ElevatedAdmin = il >= integrityHigh
	}
	return id, nil
}

func tokenUint32(tok windows.Token, class uint32) (uint32, error) {
	var v, n uint32
	if err := windows.GetTokenInformation(tok, class, (*byte)(unsafe.Pointer(&v)), 4, &n); err != nil {
		return 0, err
	}
	return v, nil
}

// integrity is the token's mandatory integrity level (its label's RID).
func integrity(tok windows.Token) (uint32, error) {
	buf := make([]byte, 128)
	var n uint32
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], uint32(len(buf)), &n); err != nil {
		return 0, err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := label.Label.Sid
	c := sid.SubAuthorityCount()
	if c == 0 {
		return 0, errors.New("no integrity level")
	}
	return sid.SubAuthority(uint32(c - 1)), nil
}

// Dial opens the channel as a client: at identification level, so a
// server that is not the service can't act as this user; then it checks
// that the pipe's owner is the service, through the open handle, before
// anything is sent; then the hellos. Errors: ErrNoService (no such
// pipe), ErrNotService (another owner: a squatted name), ErrAccessDenied
// (the pipe's access list refused this account at open, or a remote
// client), ErrNotAllowed (the service refused this operation to this
// account), ErrMemberIsAdmin (tools refused to a member who is an
// administrator), ErrBusy, ErrInUse, ErrVersionsDiffer.
func Dial(ctx context.Context, cfg DialConfig) (*os.File, error) {
	want, err := windows.StringToSid(cfg.Service)
	if err != nil {
		return nil, fmt.Errorf("the service's SID: %w", err)
	}
	full := PipePath(cfg.Pipe)
	if cfg.server != "" {
		full = `\\` + cfg.server + `\pipe\` + cfg.Pipe
	}
	path, err := windows.UTF16PtrFromString(full)
	if err != nil {
		return nil, err
	}
	wait := cfg.Wait
	if wait <= 0 {
		wait = 5 * time.Second
	}
	deadline := time.Now().Add(wait)
	flags := uint32(windows.FILE_FLAG_OVERLAPPED | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION)
	if cfg.anonymous {
		flags = windows.FILE_FLAG_OVERLAPPED | windows.SECURITY_SQOS_PRESENT | windows.SECURITY_ANONYMOUS
	}
	var h windows.Handle
	for {
		h, err = windows.CreateFile(path, clientAccess, 0, nil, windows.OPEN_EXISTING, flags, 0)
		if err == nil {
			break
		}
		switch {
		case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
			return nil, ErrNoService
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return nil, ErrAccessDenied
		case errors.Is(err, windows.ERROR_PIPE_BUSY):
			left := time.Until(deadline)
			if left <= 0 || ctx.Err() != nil {
				return nil, fmt.Errorf("the connector's channel is busy: %w", err)
			}
			_, _, _ = procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(path)), uintptr(min(left, time.Second)/time.Millisecond))
			continue
		default:
			return nil, fmt.Errorf("the connector's channel can't be opened: %w", err)
		}
	}
	if err := checkOwner(h, want); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	f := os.NewFile(uintptr(h), full)
	_ = f.SetDeadline(time.Now().Add(helloWait))
	stop := context.AfterFunc(ctx, func() { _ = f.SetDeadline(time.Now()) })
	err = clientHandshake(f, cfg.Op, cfg.Version)
	if !stop() && err != nil {
		err = errors.Join(ctx.Err(), err)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	_ = f.SetDeadline(time.Time{})
	return f, nil
}

// checkOwner reads the owner of the pipe through the open handle (not
// by name, and not by the server's process id, which can be reused).
func checkOwner(h windows.Handle, want *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("the channel's owner can't be read: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("the channel's owner can't be read: %v", err)
	}
	if !windows.EqualSid(owner, want) {
		return ErrNotService
	}
	return nil
}

// holdsGroup reports whether the token lists group among its groups,
// enabled or not, deny-only included.
func holdsGroup(tok windows.Token, group *windows.SID) (bool, error) {
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return false, err
	}
	for _, g := range groups.AllGroups() {
		if windows.EqualSid(g.Sid, group) {
			return true, nil
		}
	}
	return false, nil
}
