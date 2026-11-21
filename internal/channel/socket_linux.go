//go:build linux

package channel

// The channel's Unix-socket end on Linux (AGENT-PLAN §6 A5.6;
// AGENT-SEPARATE-ACCOUNT §4; AGENT-LINUX-RUNTIME §3). systemd makes the
// socket, /run/vettid-agent/<n>.sock, owned by the connector's account
// and the member's group, 0660, in a root-owned folder, and hands it to
// the service by socket activation. The service never makes or binds a
// socket. It knows each client by the uid the kernel recorded at connect
// (SO_PEERCRED), never by its process id or anything the client says.
// Every client checks the socket, its folder and the server's uid before
// it sends anything.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// SocketDir is the folder systemd makes the channel's socket in
// (DirectoryMode=0755, owned by root).
const SocketDir = "/run/vettid-agent"

const (
	// maxConns bounds the clients connected at once; one beyond it is
	// told the channel is busy (chosen; not in the spec; as on Windows).
	maxConns = 16
	// helloWait bounds each end's hello (chosen; not in the spec).
	helloWait = 10 * time.Second
	// activationFD is the first descriptor systemd passes
	// (SD_LISTEN_FDS_START).
	activationFD = 3
)

// adminGroups are the groups that make the member an administrator on
// Linux (AGENT-LINUX-RUNTIME §11, proposed and open for the owner): the
// member then gets member_is_admin for every tool, as on Windows. Until
// the owner decides, this fails closed.
var adminGroups = []string{"sudo", "wheel", "admin"}

// ErrNotActivated: the service was not started by its systemd socket.
var ErrNotActivated = errors.New("the connector service must be started by its systemd socket, not by hand")

// SocketPath is pairing n's socket.
func SocketPath(n string) string { return filepath.Join(SocketDir, n+".sock") }

// ServiceAccount is the account that must own pairing n's channel, as
// the client checks it: the connector's system user.
func ServiceAccount(n string) string { return ConnectorUser(n) }

// ReadPipe returns pairing n's socket. On Linux the stub reads no
// configuration: the socket's path comes from the name, and the
// account that must own it from the name's hash (AGENT-LINUX-RUNTIME
// §10).
func ReadPipe(n string) (string, error) {
	if !ValidName(n) {
		return "", fmt.Errorf("%q is not a pairing's name: use 1 to 32 lowercase letters, digits or hyphens, starting with a letter or digit", n)
	}
	return SocketPath(n), nil
}

// ListenConfig configures Listen.
type ListenConfig struct {
	// Socket is the path systemd bound the socket to; Listen refuses a
	// socket bound anywhere else.
	Socket string
	// MemberUID is the member's uid, from the service's configuration.
	MemberUID uint32
	// MemberAdmin: install found a sudo rule that gives the member root
	// (sudo -l, which only root can read), so the member is an
	// administrator whatever its groups.
	MemberAdmin bool
	// Version is this program's version; a client of another version is
	// refused.
	Version string
	// OnRefused, if set, is told of each client refused before Accept
	// returns it (its operation if it named one, and why). It must not
	// block.
	OnRefused func(op Op, err error)

	fd       int                                     // tests only: the listening descriptor, in place of systemd's
	groupsOf func(uid, gid uint32) ([]string, error) // tests only: the member's groups
}

// Listener is the server end: the service's. Accept is called from one
// goroutine at a time.
type Listener struct {
	cfg ListenConfig
	f   *os.File

	mu     sync.Mutex
	closed bool
	live   int // clients connected and not yet closed (maxConns)
}

// errClosed: the listener was closed.
var errClosed = errors.New("the channel is closed")

// Listen takes the socket systemd passed (LISTEN_PID naming this
// process, LISTEN_FDS exactly 1) and checks that it is a listening Unix
// stream socket bound to cfg.Socket. It never makes a socket itself.
func Listen(cfg ListenConfig) (*Listener, error) {
	if cfg.MemberUID == 0 {
		return nil, errors.New("the member can't be root")
	}
	fd := cfg.fd
	if fd == 0 {
		var err error
		if fd, err = takeActivationFD(); err != nil {
			return nil, err
		}
	}
	if err := checkListening(fd, cfg.Socket); err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if cfg.groupsOf == nil {
		cfg.groupsOf = userGroups
	}
	return &Listener{cfg: cfg, f: os.NewFile(uintptr(fd), cfg.Socket)}, nil
}

// takeActivationFD reads systemd's activation variables, removes them
// (so nothing this process starts sees them), and returns fd 3.
func takeActivationFD() (int, error) {
	pid, fds := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	for _, v := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(v)
	}
	if pid != strconv.Itoa(os.Getpid()) || fds != "1" {
		return 0, ErrNotActivated
	}
	return activationFD, nil
}

// checkListening checks that fd is a listening AF_UNIX stream socket
// bound to path.
func checkListening(fd int, path string) error {
	bad := func(what string) error {
		return fmt.Errorf("%w: the descriptor systemd passed is %s", ErrNotActivated, what)
	}
	if d, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN); err != nil || d != unix.AF_UNIX {
		return bad("not a Unix socket")
	}
	if ty, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || ty != unix.SOCK_STREAM {
		return bad("not a stream socket")
	}
	if l, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN); err != nil || l != 1 {
		return bad("not listening")
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return bad("unnamed")
	}
	if u, ok := sa.(*unix.SockaddrUnix); !ok || u.Name != path {
		return bad("bound to another path")
	}
	return nil
}

// Close stops Accept. Connections already accepted stay open.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.f.Close()
}

// ServerConn is an admitted client, waiting for the service's answer:
// Accept (the operation's bytes follow) or Refuse. Close it with
// ServerConn.Close (or Refuse), never through the embedded File: only
// ServerConn.Close gives its place back to the maxConns count.
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

// clientError is one client's failure; Accept goes on to the next.
type clientError struct {
	op  Op
	err error
}

func (e *clientError) Error() string { return e.err.Error() }

// Accept waits for a client that names an operation it may run (Admit).
// Clients refused on the way are told so and reported to OnRefused;
// Accept returns only an admitted client, or an error once ctx ends or
// the listener is closed.
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

// longAgo is a deadline in the past, which wakes a waiting accept.
var longAgo = time.Unix(1, 0)

// acceptFD waits for one connection until ctx ends.
func (l *Listener) acceptFD(ctx context.Context) (int, error) {
	if err := l.f.SetReadDeadline(time.Time{}); err != nil {
		return 0, l.closedOr(err)
	}
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = l.f.SetReadDeadline(longAgo)
		close(fired)
	})
	defer func() {
		if !stop() {
			<-fired
		}
	}()
	rc, err := l.f.SyscallConn()
	if err != nil {
		return 0, l.closedOr(err)
	}
	nfd := -1
	var aerr error
	err = rc.Read(func(fd uintptr) bool {
		nfd, _, aerr = unix.Accept4(int(fd), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		return aerr != unix.EAGAIN
	})
	switch {
	case err != nil && ctx.Err() != nil:
		return 0, ctx.Err()
	case err != nil:
		return 0, l.closedOr(err)
	case aerr == unix.ECONNABORTED, aerr == unix.EPROTO:
		// A client that came and left before the connection.
		return 0, &clientError{err: aerr}
	case aerr != nil:
		return 0, fmt.Errorf("the channel can't accept a connection: %w", aerr)
	}
	return nfd, nil
}

func (l *Listener) closedOr(err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errClosed
	}
	return err
}

func (l *Listener) acceptOne(ctx context.Context) (*ServerConn, error) {
	nfd, err := l.acceptFD(ctx)
	if err != nil {
		return nil, err
	}
	// The credentials the kernel recorded when the client connected:
	// they can't be changed by the client afterwards.
	cred, cerr := unix.GetsockoptUcred(nfd, unix.SOL_SOCKET, unix.SO_PEERCRED)

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		unix.Close(nfd)
		return nil, errClosed
	}
	l.live++
	busy := l.live > maxConns
	l.mu.Unlock()

	c := &ServerConn{File: os.NewFile(uintptr(nfd), l.cfg.Socket), version: l.cfg.Version, l: l}
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
	var id Identity
	if cerr != nil {
		err = fmt.Errorf("the client's credentials can't be read: %w", cerr)
	} else if id, err = l.identify(cred); err == nil {
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

// identify maps a client's uid to who it is: the member, or root (a
// command under sudo, the only elevated administrator on Linux). Anyone
// else holds nothing, and Admit refuses them. The member's
// administrator groups are read at each connection; if they can't be,
// the client is refused.
func (l *Listener) identify(cred *unix.Ucred) (Identity, error) {
	id := Identity{Member: cred.Uid == l.cfg.MemberUID, ElevatedAdmin: cred.Uid == 0}
	if !id.Member {
		return id, nil
	}
	if l.cfg.MemberAdmin {
		id.HoldsAdmins = true
		return id, nil
	}
	groups, err := l.cfg.groupsOf(cred.Uid, cred.Gid)
	if err != nil {
		return Identity{}, fmt.Errorf("the member's groups can't be read: %w", err)
	}
	id.HoldsAdmins = slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(adminGroups, g) })
	return id, nil
}

// userGroups names the groups of uid in the system's group database, with
// gid (the group the client connected with) among them.
func userGroups(uid, gid uint32) ([]string, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, err
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	ids = append(ids, strconv.FormatUint(uint64(gid), 10))
	var names []string
	for _, id := range ids {
		g, err := user.LookupGroupId(id)
		if err != nil {
			var unknown user.UnknownGroupIdError
			if errors.As(err, &unknown) {
				continue // a gid without a name can't be one of adminGroups
			}
			return nil, err
		}
		names = append(names, g.Name)
	}
	return names, nil
}

// Dial checks the socket and its folder, connects, checks the server's
// uid, and runs the hello:
//   - the socket must be a socket, not a link, owned by cfg.Service;
//   - its folder must be a folder owned by root with no group or other
//     write, so nobody else can swap the socket between the check and
//     the connection;
//   - the server's uid (SO_PEERCRED: with socket activation, the uid
//     that called listen, systemd's) must be root or cfg.Service.
//
// A missing socket is ErrNoService; one that fails a check, or a server
// of another uid, is ErrNotService; a socket the account may not open is
// ErrAccessDenied. Nothing is sent before every check has passed.
func Dial(ctx context.Context, cfg DialConfig) (*os.File, error) {
	svc, err := user.Lookup(cfg.Service)
	if err != nil {
		// No connector account: the pairing isn't installed here.
		return nil, fmt.Errorf("%w: %v", ErrNoService, err)
	}
	svcUID, err := strconv.ParseUint(svc.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: the connector account's uid: %v", ErrNoService, err)
	}
	dirUID := uint32(0)
	if cfg.dirUID != nil {
		dirUID = *cfg.dirUID
	}
	if err := checkSocket(cfg.Pipe, uint32(svcUID), dirUID); err != nil {
		return nil, err
	}
	f, err := connectUnix(ctx, cfg.Pipe, cfg.Wait)
	if err != nil {
		return nil, err
	}
	if err := checkServer(f, uint32(svcUID)); err != nil {
		f.Close()
		return nil, err
	}
	_ = f.SetDeadline(time.Now().Add(helloWait))
	stop := context.AfterFunc(ctx, func() { _ = f.SetDeadline(longAgo) })
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

// checkSocket checks the socket at path (owner svcUID) and its folder
// (owner dirUID, no group or other write).
func checkSocket(path string, svcUID, dirUID uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return ErrNoService
		}
		if errors.Is(err, unix.EACCES) {
			return ErrAccessDenied
		}
		return fmt.Errorf("%w: %v", ErrNoService, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFSOCK:
		return fmt.Errorf("%w: %s is not a socket", ErrNotService, path)
	case st.Uid != svcUID:
		return fmt.Errorf("%w: %s is owned by uid %d", ErrNotService, path, st.Uid)
	}
	dir := filepath.Dir(path)
	if err := unix.Lstat(dir, &st); err != nil {
		return fmt.Errorf("%w: %v", ErrNotService, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return fmt.Errorf("%w: %s is not a folder", ErrNotService, dir)
	case st.Uid != dirUID:
		return fmt.Errorf("%w: %s is owned by uid %d", ErrNotService, dir, st.Uid)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%w: other accounts can change %s", ErrNotService, dir)
	}
	return nil
}

// connectUnix opens a stream connection to path. A full queue is retried
// until wait ends.
func connectUnix(ctx context.Context, path string, wait time.Duration) (*os.File, error) {
	if wait <= 0 {
		wait = 5 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: path})
		if err == nil {
			return os.NewFile(uintptr(fd), path), nil
		}
		unix.Close(fd)
		switch {
		case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ECONNREFUSED):
			return nil, ErrNoService
		case errors.Is(err, unix.EACCES), errors.Is(err, unix.EPERM):
			return nil, ErrAccessDenied
		case errors.Is(err, unix.EAGAIN):
			if time.Now().After(deadline) || ctx.Err() != nil {
				return nil, fmt.Errorf("%w: %v", ErrBusy, err)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
		default:
			return nil, fmt.Errorf("the connector's channel can't be opened: %w", err)
		}
	}
}

// checkServer reads the server's uid (SO_PEERCRED): root (systemd, which
// called listen) or the connector's account.
func checkServer(f *os.File, svcUID uint32) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if cerr != nil {
		return fmt.Errorf("%w: the server's credentials can't be read: %v", ErrNotService, cerr)
	}
	if cred.Uid != 0 && cred.Uid != svcUID {
		return fmt.Errorf("%w: the server runs as uid %d", ErrNotService, cred.Uid)
	}
	return nil
}
