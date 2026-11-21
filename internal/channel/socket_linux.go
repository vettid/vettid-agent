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
	"unsafe"

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
// Linux (owner decision a, GC #15946; AGENT-LINUX-RUNTIME §11): sudo's
// usual groups, and the groups that give root in all but name (a
// container or VM manager, raw disks, the root group, the shadow file,
// every log): groups that read what root reads. The member then gets
// member_is_admin for every tool, as on Windows. A held gid 0 counts
// whatever its name.
var adminGroups = []string{"sudo", "wheel", "admin", "docker", "lxd", "incus-admin", "libvirt", "libvirtd",
	"microk8s", "disk", "root", "shadow", "adm", "systemd-journal"}

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

	fd           int                                     // tests only: the listening descriptor, in place of systemd's
	groupsOf     func(uid, gid uint32) ([]string, error) // tests only: the member's groups in the group database
	peerNames    func(gids []uint32) ([]string, error)   // tests only: the names of the groups the client holds
	peerGroupsOf func(fd, n int) ([]uint32, error)       // tests only: SO_PEERGROUPS
	peerInit     int                                     // tests only: peerGroups' first buffer, in groups (0: 64)
	helloWait    time.Duration                           // tests only: the hello's limit (0: helloWait)
	afterAccept  func(*Listener)                         // tests only: runs after each connection is accepted
}

// Listener is the server end: the service's. One goroutine accepts
// connections and drops at once any client that is neither the member,
// root nor the connector's own account; each other client's hello is
// read on a goroutine of its own, so a client that sends nothing holds
// up nobody else. Accept may be called from any goroutine.
type Listener struct {
	cfg ListenConfig
	f   *os.File
	own uint32 // this process's uid: the connector's account

	once  sync.Once
	ready chan *ServerConn // admitted clients, for Accept
	fatal chan error       // why the accept loop ended by itself
	done  chan struct{}    // closed by Close

	mu      sync.Mutex
	closed  bool
	live    int                   // clients connected and not yet closed (maxConns)
	inHello map[*os.File]struct{} // connections whose hello is being read
}

// errClosed: the listener was closed.
var errClosed = errors.New("the channel is closed")

// nobodyUID is the overflow uid a user namespace gives every user it
// doesn't map. A member of that uid would be every such user.
const nobodyUID = 65534

// cleanAbs reports whether p is an absolute path in clean form.
func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

// Listen takes the socket systemd passed (LISTEN_PID naming this
// process, LISTEN_FDS exactly 1) and checks that it is a listening Unix
// stream socket bound to cfg.Socket, made by root (systemd). It never
// makes a socket itself.
func Listen(cfg ListenConfig) (*Listener, error) {
	switch cfg.MemberUID {
	case 0:
		return nil, errors.New("the member can't be root")
	case nobodyUID:
		return nil, errors.New("the member can't be uid 65534, which a user namespace gives every user it doesn't map")
	}
	if !cleanAbs(cfg.Socket) {
		return nil, fmt.Errorf("%w: the socket's path %q is not absolute and clean", ErrNotActivated, cfg.Socket)
	}
	fd := cfg.fd
	activated := fd == 0
	if activated {
		var err error
		if fd, err = takeActivationFD(); err != nil {
			return nil, err
		}
	}
	if err := checkListening(fd, cfg.Socket, activated); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	unix.CloseOnExec(fd)
	if cfg.groupsOf == nil {
		cfg.groupsOf = userGroups
	}
	if cfg.peerNames == nil {
		cfg.peerNames = groupNames
	}
	if cfg.peerGroupsOf == nil {
		cfg.peerGroupsOf = peerGroups
	}
	if cfg.helloWait == 0 {
		cfg.helloWait = helloWait
	}
	return &Listener{
		cfg: cfg, f: os.NewFile(uintptr(fd), cfg.Socket), own: uint32(os.Getuid()),
		ready: make(chan *ServerConn), fatal: make(chan error, 1), done: make(chan struct{}),
		inHello: map[*os.File]struct{}{},
	}, nil
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
// bound to path; with activated, also that root called listen on it
// (systemd, which made it).
func checkListening(fd int, path string, activated bool) error {
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
	if activated {
		if cred, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED); err != nil || cred.Uid != 0 {
			return bad("not made by root")
		}
	}
	return nil
}

// Close stops Accept, and ends every hello still being read.
// Connections already accepted stay open.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	for f := range l.inHello {
		_ = f.SetDeadline(longAgo)
	}
	close(l.done)
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
	// uncounted: root's, which doesn't count toward maxConns.
	uncounted bool
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
		if c.uncounted {
			return
		}
		c.l.mu.Lock()
		c.l.live--
		c.l.mu.Unlock()
	})
	return err
}

// clientError is one client's failure; the loop goes on to the next.
type clientError struct {
	op  Op
	err error
}

func (e *clientError) Error() string { return e.err.Error() }

// Accept waits for a client that names an operation it may run (Admit).
// Clients refused on the way are told so and reported to OnRefused,
// which may then be called from several goroutines at once. Accept
// returns only an admitted client, or an error once ctx ends, the
// listener is closed, or the socket can't be used any more.
func (l *Listener) Accept(ctx context.Context) (*ServerConn, error) {
	l.once.Do(func() { go l.loop() })
	select {
	case c := <-l.ready:
		l.mu.Lock()
		closed := l.closed
		l.mu.Unlock()
		if closed {
			// Never hand out a client once Close has begun.
			c.Close()
			return nil, errClosed
		}
		return c, nil
	case err := <-l.fatal:
		l.fatal <- err // for the next call too
		return nil, err
	case <-l.done:
		return nil, errClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// longAgo is a deadline in the past, which wakes a waiting read.
var longAgo = time.Unix(1, 0)

func (l *Listener) refused(op Op, err error) {
	if l.cfg.OnRefused != nil {
		l.cfg.OnRefused(op, err)
	}
}

// loop accepts connections until the listener is closed.
func (l *Listener) loop() {
	for {
		nfd, err := l.acceptFD()
		if err != nil {
			var ce *clientError
			if errors.As(err, &ce) {
				l.refused(ce.op, ce.err)
				continue
			}
			if !errors.Is(err, errClosed) {
				l.fatal <- err
			}
			return
		}
		if l.cfg.afterAccept != nil {
			l.cfg.afterAccept(l)
		}
		l.admit(nfd)
	}
}

// acceptFD waits for one connection.
func (l *Listener) acceptFD() (int, error) {
	rc, err := l.f.SyscallConn()
	if err != nil {
		return 0, l.closedOr(err)
	}
	nfd := -1
	var aerr error
	err = rc.Read(func(fd uintptr) bool {
		for {
			nfd, _, aerr = unix.Accept4(int(fd), unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
			if aerr != unix.EINTR {
				break
			}
		}
		// EAGAIN: wait for the socket again.
		return aerr != unix.EAGAIN
	})
	switch {
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

// admit sorts a new connection before reading anything from it: by the
// credentials the kernel recorded at connect, which the client can't
// change afterwards.
func (l *Listener) admit(nfd int) {
	cred, err := unix.GetsockoptUcred(nfd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		unix.Close(nfd)
		l.refused("", fmt.Errorf("the client's credentials can't be read: %w", err))
		return
	}
	if cred.Uid != l.cfg.MemberUID && cred.Uid != 0 && cred.Uid != l.own {
		// Nobody else may use the channel: dropped before its hello.
		unix.Close(nfd)
		l.refused("", ErrNotAllowed)
		return
	}
	var gids []uint32
	var gerr error
	if cred.Uid == l.cfg.MemberUID {
		gids, gerr = l.cfg.peerGroupsOf(nfd, l.cfg.peerInit)
	}
	f := os.NewFile(uintptr(nfd), l.cfg.Socket)
	// The hello's limit is set before Close can see the connection, so
	// Close's deadline is never overwritten.
	_ = f.SetDeadline(time.Now().Add(l.cfg.helloWait))
	// Root (an elevated command) never counts against maxConns and
	// always gets its hello read, so the member's connections can't keep
	// status, pair or forget out (chosen; not in the spec).
	counted := cred.Uid != 0
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		f.Close()
		return
	}
	busy := false
	if counted {
		l.live++
		// Past twice maxConns a client is dropped without an answer, so
		// the goroutines reading hellos stay bounded; past maxConns it is
		// told the channel is busy once its hello is read.
		if l.live > 2*maxConns {
			l.live--
			l.mu.Unlock()
			f.Close()
			l.refused("", ErrBusy)
			return
		}
		busy = l.live > maxConns
	}
	l.inHello[f] = struct{}{}
	l.mu.Unlock()
	c := &ServerConn{File: f, version: l.cfg.Version, l: l, uncounted: !counted}
	go l.hello(c, busy, cred, gids, gerr)
}

// hello reads a client's hello, judges it, and hands an admitted client
// to Accept.
func (l *Listener) hello(c *ServerConn, busy bool, cred *unix.Ucred, gids []uint32, gerr error) {
	op, err := readClientHello(c.File, l.cfg.Version)
	l.mu.Lock()
	delete(l.inHello, c.File)
	closed := l.closed
	l.mu.Unlock()
	switch {
	case closed:
		c.Close()
		return
	case err != nil:
		c.Close()
		l.refused(op, err)
		return
	case busy:
		_ = refuse(c.File, l.cfg.Version, ErrBusy)
		c.Close()
		l.refused(op, ErrBusy)
		return
	}
	var id Identity
	if gerr != nil {
		err = fmt.Errorf("the client's groups can't be read: %w", gerr)
	} else if id, err = l.identify(cred, gids); err == nil {
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
		l.refused(op, err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	c.Op, c.Identity = op, id
	select {
	case l.ready <- c:
	case <-l.done:
		c.Close()
	}
}

// identify maps a client's uid to who it is: the member, or root (a
// command under sudo, the only elevated administrator on Linux). Anyone
// else holds nothing, and Admit refuses them. The member is an
// administrator if the group database or the groups the client holds
// (gids, SO_PEERGROUPS) name one of adminGroups: both are read at each
// connection, and if either can't be, the client is refused.
func (l *Listener) identify(cred *unix.Ucred, gids []uint32) (Identity, error) {
	id := Identity{Member: cred.Uid == l.cfg.MemberUID, ElevatedAdmin: cred.Uid == 0}
	if !id.Member {
		return id, nil
	}
	if l.cfg.MemberAdmin || cred.Gid == 0 || slices.Contains(gids, 0) {
		id.HoldsAdmins = true
		return id, nil
	}
	groups, err := l.cfg.groupsOf(cred.Uid, cred.Gid)
	if err != nil {
		return Identity{}, fmt.Errorf("the member's groups can't be read: %w", err)
	}
	held, err := l.cfg.peerNames(gids)
	if err != nil {
		return Identity{}, fmt.Errorf("the client's groups can't be named: %w", err)
	}
	groups = append(groups, held...)
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
	return lookupGroups(ids)
}

// groupNames names the groups gids.
func groupNames(gids []uint32) ([]string, error) {
	ids := make([]string, len(gids))
	for i, g := range gids {
		ids[i] = strconv.FormatUint(uint64(g), 10)
	}
	return lookupGroups(ids)
}

func lookupGroups(ids []string) ([]string, error) {
	var names []string
	for _, id := range ids {
		g, err := user.LookupGroupId(id)
		if err != nil {
			// A gid this lookup can't name may be an administrator's group
			// from NSS (LDAP, sssd), which a build without cgo doesn't read:
			// fail closed (chosen; not in the spec).
			return nil, fmt.Errorf("group %s has no name in the local group database: %w", id, err)
		}
		names = append(names, g.Name)
	}
	return names, nil
}

// peerGroups reads the supplementary groups the client held when it
// connected (SO_PEERGROUPS, Linux 4.13).
func peerGroups(fd, n int) ([]uint32, error) {
	if n <= 0 {
		n = 64
	}
	for {
		buf := make([]uint32, n)
		size := uint32(4 * n)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch {
		case errno == unix.ERANGE && int(size)/4 > n:
			n = int(size) / 4
			continue
		case errno != 0:
			return nil, errno
		}
		return buf[:size/4], nil
	}
}

// Dial checks the socket and its folder, connects, checks the server's
// uid, and runs the hello:
//   - the socket must be a socket, not a link, owned by cfg.Service;
//   - its folder, and every folder above it up to /, must be a folder
//     owned by root with no group or other write, so nobody else can
//     swap the socket between the check and the connection;
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
	dirUID, walk := uint32(0), true
	if cfg.dirUID != nil {
		dirUID, walk = *cfg.dirUID, false
	}
	if err := checkSocket(cfg.Pipe, uint32(svcUID), dirUID, walk); err != nil {
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
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = f.SetDeadline(longAgo)
		close(fired)
	})
	err = clientHandshake(f, cfg.Op, cfg.Version)
	if err != nil && !knownRefusal(err) {
		// The server hung up mid-hello (a write's EPIPE, a read's reset):
		// a client the service drops before its hello sees this.
		err = fmt.Errorf("%w: %v", ErrBadHello, err)
	}
	if !stop() {
		<-fired // the deadline it set is reset below, or f is closed
		if err == nil {
			err = ctx.Err()
		} else {
			err = errors.Join(ctx.Err(), err)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	_ = f.SetDeadline(time.Time{})
	return f, nil
}

// knownRefusal reports whether err is one of the hello's own outcomes.
func knownRefusal(err error) bool {
	for _, e := range []error{ErrBadHello, ErrVersionsDiffer, ErrNotAllowed, ErrInUse, ErrBusy, ErrMemberIsAdmin} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// checkSocket checks the socket at path (owner svcUID) and its folder
// (owner dirUID, no group or other write); with walk, every folder above
// it too, up to /, each owned by root with no group or other write, so
// no other account can replace any of them.
func checkSocket(path string, svcUID, dirUID uint32, walk bool) error {
	if !cleanAbs(path) {
		return fmt.Errorf("%w: the socket's path %q is not absolute and clean", ErrNotService, path)
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return ErrNoService
		}
		if errors.Is(err, unix.EACCES) {
			return ErrAccessDenied
		}
		return fmt.Errorf("%w: %v", ErrNotService, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFSOCK:
		return fmt.Errorf("%w: %s is not a socket", ErrNotService, path)
	case st.Uid != svcUID:
		return fmt.Errorf("%w: %s is owned by uid %d", ErrNotService, path, st.Uid)
	}
	dir := filepath.Dir(path)
	for {
		if err := checkFolder(dir, dirUID); err != nil {
			return err
		}
		if !walk || dir == "/" {
			return nil
		}
		dir, dirUID = filepath.Dir(dir), 0
	}
}

// checkFolder checks that dir is a folder (not a link) owned by uid with
// no group or other write.
func checkFolder(dir string, uid uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return fmt.Errorf("%w: %v", ErrNotService, err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return fmt.Errorf("%w: %s is not a folder", ErrNotService, dir)
	case st.Uid != uid:
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
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if time.Now().After(deadline) {
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
