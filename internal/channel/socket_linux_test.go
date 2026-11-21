//go:build linux

package channel

// Tests of the Unix-socket end that need no root: the descriptor checks,
// the activation variables, who a client is, and the client's checks of
// the socket and its folder, all with this process's own uid as the
// member, the connector and the folder's owner. The root tests
// (socket_root_linux_test.go) run the real systemd socket, other users
// and root.

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// listenAt makes a listening Unix stream socket at path, as systemd
// would, and returns its descriptor.
func listenAt(t *testing.T, path string) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 16); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	return fd
}

// me is this process's uid and user name.
func me(t *testing.T) (uint32, string) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	if uid == 0 {
		// These tests make this process's own uid the member, and root
		// can't be the member. The root tests run the other accounts.
		t.Skip("run as a normal user; as root, run the TestRoot tests")
	}
	return uint32(uid), u.Username
}

// shortDir is a folder for sockets: a socket's path must be short
// (108 bytes), which t.TempDir's may not be. It is 0700, so no group or
// other write.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "vtch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// recv takes the next value from ch, failing the test after 5 s, so a
// client the server didn't see fails rather than hangs.
func recv[T any](t *testing.T, ch chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("the server saw no client")
		var zero T
		return zero
	}
}

func TestSocketNames(t *testing.T) {
	if got, want := SocketPath("work"), "/run/vettid-agent/work.sock"; got != want {
		t.Errorf("SocketPath = %q, want %q", got, want)
	}
	if got, want := ServiceAccount("work"), ConnectorUser("work"); got != want {
		t.Errorf("ServiceAccount = %q, want %q", got, want)
	}
	if p, err := ReadPipe("work"); err != nil || p != SocketPath("work") {
		t.Errorf("ReadPipe = %q, %v", p, err)
	}
	if _, err := ReadPipe("../x"); err == nil {
		t.Error("ReadPipe took a name that isn't a pairing's")
	}
}

func TestListenChecksTheDescriptor(t *testing.T) {
	uid, _ := me(t)
	d := shortDir(t)
	path := filepath.Join(d, "a.sock")
	fd := listenAt(t, path)
	l, err := Listen(ListenConfig{Socket: path, MemberUID: uid + 1, fd: fd})
	if err != nil {
		t.Fatalf("Listen on a good socket: %v", err)
	}
	l.Close()

	other := filepath.Join(d, "b.sock")
	fd = listenAt(t, other)
	if _, err := Listen(ListenConfig{Socket: path, MemberUID: uid + 1, fd: fd}); !errors.Is(err, ErrNotActivated) {
		t.Errorf("a socket bound to another path: %v, want ErrNotActivated", err)
	}
	// Listen closed the descriptor it refused.
	if _, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE); !errors.Is(err, unix.EBADF) {
		t.Errorf("a refused descriptor is still open: %v", err)
	}

	// Not listening.
	nl, _ := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	_ = unix.Bind(nl, &unix.SockaddrUnix{Name: filepath.Join(d, "c.sock")})
	if _, err := Listen(ListenConfig{Socket: filepath.Join(d, "c.sock"), MemberUID: uid + 1, fd: nl}); !errors.Is(err, ErrNotActivated) {
		t.Errorf("a socket not listening: %v", err)
	}

	// A datagram socket.
	dg, _ := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	_ = unix.Bind(dg, &unix.SockaddrUnix{Name: filepath.Join(d, "d.sock")})
	if _, err := Listen(ListenConfig{Socket: filepath.Join(d, "d.sock"), MemberUID: uid + 1, fd: dg}); !errors.Is(err, ErrNotActivated) {
		t.Errorf("a datagram socket: %v", err)
	}

	// A TCP socket.
	tcp, _ := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	_ = unix.Bind(tcp, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	_ = unix.Listen(tcp, 1)
	if _, err := Listen(ListenConfig{Socket: path, MemberUID: uid + 1, fd: tcp}); !errors.Is(err, ErrNotActivated) {
		t.Errorf("a TCP socket: %v", err)
	}

	if _, err := Listen(ListenConfig{Socket: path, MemberUID: 0, fd: 1}); err == nil {
		t.Error("Listen took root as the member")
	}
}

func TestActivationVariables(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	for _, c := range []struct{ pid, fds string }{
		{"", ""},
		{strconv.Itoa(os.Getpid() + 1), "1"}, // meant for another process
		{pid, "2"},
		{pid, "0"},
	} {
		t.Setenv("LISTEN_PID", c.pid)
		t.Setenv("LISTEN_FDS", c.fds)
		if _, err := takeActivationFD(); !errors.Is(err, ErrNotActivated) {
			t.Errorf("LISTEN_PID %q LISTEN_FDS %q: %v, want ErrNotActivated", c.pid, c.fds, err)
		}
	}
	t.Setenv("LISTEN_PID", pid)
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "x")
	fd, err := takeActivationFD()
	if err != nil || fd != 3 {
		t.Fatalf("takeActivationFD = %d, %v", fd, err)
	}
	for _, v := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		if _, ok := os.LookupEnv(v); ok {
			t.Errorf("%s is still set", v)
		}
	}
}

// serve runs a listener on its own goroutine: each admitted client is
// accepted and told its identity's member bit, then closed.
type served struct {
	ids     chan Identity
	refused chan error
}

func serve(t *testing.T, cfg ListenConfig) (path string, s served) {
	t.Helper()
	d := shortDir(t)
	path = filepath.Join(d, "s.sock")
	cfg.fd = listenAt(t, path)
	cfg.Socket = path
	if cfg.peerNames == nil {
		// This test user's real groups (which may hold sudo) don't decide
		// here; TestRootMemberIsAdmin runs the real lookup.
		cfg.peerNames = func([]uint32) ([]string, error) { return nil, nil }
	}
	s = served{ids: make(chan Identity, 8), refused: make(chan error, 8)}
	cfg.OnRefused = func(_ Op, err error) { s.refused <- err }
	if cfg.Version == "" {
		cfg.Version = "v1"
	}
	l, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); l.Close(); <-done })
	go func() {
		defer close(done)
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			s.ids <- c.Identity
			_ = c.Accept()
			c.Close()
		}
	}()
	return path, s
}

func dialAs(t *testing.T, path string, op Op) error {
	t.Helper()
	uid, name := me(t)
	f, err := Dial(context.Background(), DialConfig{Pipe: path, Service: name, Op: op, Version: "v1", dirUID: &uid})
	if err == nil {
		f.Close()
	}
	return err
}

func TestAcceptKnowsTheMember(t *testing.T) {
	uid, _ := me(t)
	noGroups := func(uint32, uint32) ([]string, error) { return []string{"users"}, nil }
	path, s := serve(t, ListenConfig{MemberUID: uid, groupsOf: noGroups})

	if err := dialAs(t, path, OpMCP); err != nil {
		t.Fatalf("the member's tools: %v", err)
	}
	if id := recv(t, s.ids); !id.Member || id.ElevatedAdmin || id.HoldsAdmins {
		t.Errorf("identity %+v, want the member only", id)
	}
	if err := dialAs(t, path, OpStatus); err != nil {
		t.Errorf("the member's status: %v", err)
	}
	recv(t, s.ids)
	// pair and forget from the member's normal process: refused.
	for _, op := range []Op{OpPair, OpForget} {
		if err := dialAs(t, path, op); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s from the member: %v, want ErrNotAllowed", op, err)
		}
		if err := recv(t, s.refused); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("OnRefused got %v", err)
		}
	}
}

func TestAcceptRefusesAnotherUser(t *testing.T) {
	uid, _ := me(t)
	path, s := serve(t, ListenConfig{MemberUID: uid + 1})
	for _, op := range []Op{OpMCP, OpStatus, OpPair} {
		if err := dialAs(t, path, op); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s from another user: %v, want ErrNotAllowed", op, err)
		}
		recv(t, s.refused)
	}
}

func TestAcceptMemberIsAdmin(t *testing.T) {
	uid, _ := me(t)
	for _, g := range adminGroups {
		groups := func(uint32, uint32) ([]string, error) { return []string{"users", g}, nil }
		path, s := serve(t, ListenConfig{MemberUID: uid, groupsOf: groups})
		if err := dialAs(t, path, OpMCP); !errors.Is(err, ErrMemberIsAdmin) {
			t.Errorf("a member in %s: %v, want ErrMemberIsAdmin", g, err)
		}
		recv(t, s.refused)
		if err := dialAs(t, path, OpStatus); err != nil {
			t.Errorf("a member in %s, status: %v", g, err)
		}
		if id := recv(t, s.ids); !id.HoldsAdmins {
			t.Errorf("a member in %s: %+v", g, id)
		}
	}
	// install's sudo rule, whatever the groups.
	none := func(uint32, uint32) ([]string, error) { return nil, nil }
	path, s := serve(t, ListenConfig{MemberUID: uid, MemberAdmin: true, groupsOf: none})
	if err := dialAs(t, path, OpMCP); !errors.Is(err, ErrMemberIsAdmin) {
		t.Errorf("MemberAdmin: %v, want ErrMemberIsAdmin", err)
	}
	recv(t, s.refused)
	// A group the client holds, though the group database doesn't list it.
	held := func([]uint32) ([]string, error) { return []string{"docker"}, nil }
	path, s = serve(t, ListenConfig{MemberUID: uid, groupsOf: none, peerNames: held})
	if err := dialAs(t, path, OpMCP); !errors.Is(err, ErrMemberIsAdmin) {
		t.Errorf("a group the client holds: %v, want ErrMemberIsAdmin", err)
	}
	recv(t, s.refused)
	unnamed := func([]uint32) ([]string, error) { return nil, errors.New("no group database") }
	path, s = serve(t, ListenConfig{MemberUID: uid, groupsOf: none, peerNames: unnamed})
	if err := dialAs(t, path, OpMCP); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("unnamed client groups: %v, want ErrNotAllowed", err)
	}
	recv(t, s.refused)
	// Groups that can't be read: refused, not admitted.
	broken := func(uint32, uint32) ([]string, error) { return nil, errors.New("no group database") }
	path, s = serve(t, ListenConfig{MemberUID: uid, groupsOf: broken})
	if err := dialAs(t, path, OpMCP); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("unreadable groups: %v, want ErrNotAllowed", err)
	}
	recv(t, s.refused)
}

// peerGroups reads what the client holds: this process's own groups.
func TestPeerGroups(t *testing.T) {
	a, b, err := socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(a)
	defer unix.Close(b)
	want, err := unix.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	// From the usual buffer, and from one too small (the ERANGE retry).
	for _, start := range []int{0, 1} {
		got, err := peerGroups(a, start)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("peerGroups(start %d) = %v, Getgroups = %v", start, got, want)
		}
		for _, g := range want {
			if !slices.Contains(got, uint32(g)) {
				t.Errorf("peerGroups(start %d) = %v, missing %d", start, got, g)
			}
		}
	}
	if len(want) < 2 {
		t.Log("this process holds fewer than 2 groups, so the ERANGE retry wasn't reached")
	}
}

// A gid the local group database can't name fails closed: it may be an
// administrator's group from NSS.
func TestGroupNamesUnknownFails(t *testing.T) {
	if _, err := groupNames([]uint32{4000000123}); err == nil {
		t.Error("groupNames named a gid that has no name")
	}
}

func socketpair() (int, int, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	return fds[0], fds[1], err
}

func TestUserGroups(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	names, err := userGroups(uint32(uid), uint32(gid))
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skip("this user's primary group has no name")
	}
	found := false
	for _, n := range names {
		found = found || n == g.Name
	}
	if !found {
		t.Errorf("userGroups = %v, want %s among them", names, g.Name)
	}
}

func TestDialChecksTheSocket(t *testing.T) {
	uid, name := me(t)
	path, s := serve(t, ListenConfig{MemberUID: uid, groupsOf: func(uint32, uint32) ([]string, error) { return nil, nil }})
	d := filepath.Dir(path)
	dial := func(p, service string, dirUID uint32) error {
		f, err := Dial(context.Background(), DialConfig{Pipe: p, Service: service, Op: OpStatus, Version: "v1", dirUID: &dirUID})
		if err == nil {
			f.Close()
			recv(t, s.ids)
		}
		return err
	}
	if err := dial(path, name, uid); err != nil {
		t.Fatalf("a good socket: %v", err)
	}
	// A link to the socket.
	link := filepath.Join(d, "link.sock")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := dial(link, name, uid); !errors.Is(err, ErrNotService) {
		t.Errorf("a link: %v, want ErrNotService", err)
	}
	// A regular file.
	file := filepath.Join(d, "file.sock")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := dial(file, name, uid); !errors.Is(err, ErrNotService) {
		t.Errorf("a file: %v, want ErrNotService", err)
	}
	// Owned by an account that isn't the connector's.
	if uid == 0 {
		t.Log("run as root: the \"another owner\" case needs another uid, so it is left to the root tests")
	} else if err := dial(path, "root", uid); !errors.Is(err, ErrNotService) {
		t.Errorf("another owner: %v, want ErrNotService", err)
	}
	// A folder owned by another uid.
	if err := dial(path, name, uid+1); !errors.Is(err, ErrNotService) {
		t.Errorf("a folder of another owner: %v, want ErrNotService", err)
	}
	// A folder others can change.
	for _, mode := range []os.FileMode{0o720, 0o702, 0o777} {
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		if err := dial(path, name, uid); !errors.Is(err, ErrNotService) {
			t.Errorf("a folder of mode %o: %v, want ErrNotService", mode, err)
		}
	}
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := dial(path, name, uid); err != nil {
		t.Errorf("a folder of mode 755: %v", err)
	}
	// Missing, and an account that doesn't exist.
	if err := dial(filepath.Join(d, "none.sock"), name, uid); !errors.Is(err, ErrNoService) {
		t.Errorf("no socket: %v, want ErrNoService", err)
	}
	if err := dial(path, "vettid-c-nobody00", uid); !errors.Is(err, ErrNoService) {
		t.Errorf("no connector account: %v, want ErrNoService", err)
	}
}

// A server of another version is refused by the client, and a hello that
// never comes ends at ctx.
func TestDialVersionAndContext(t *testing.T) {
	uid, name := me(t)
	path, _ := serve(t, ListenConfig{MemberUID: uid, Version: "v2", groupsOf: func(uint32, uint32) ([]string, error) { return nil, nil }})
	_, err := Dial(context.Background(), DialConfig{Pipe: path, Service: name, Op: OpStatus, Version: "v1", dirUID: &uid})
	if !errors.Is(err, ErrVersionsDiffer) {
		t.Errorf("another version: %v, want ErrVersionsDiffer", err)
	}

	// A listener that never answers.
	d := shortDir(t)
	silent := filepath.Join(d, "q.sock")
	fd := listenAt(t, silent)
	defer unix.Close(fd)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Dial(ctx, DialConfig{Pipe: silent, Service: name, Op: OpStatus, Version: "v1", dirUID: &uid})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a silent server: %v, want the context's deadline", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("Dial waited past its context")
	}
}

// Close ends a waiting Accept.
func TestListenerClose(t *testing.T) {
	uid, _ := me(t)
	d := shortDir(t)
	path := filepath.Join(d, "c.sock")
	l, err := Listen(ListenConfig{Socket: path, MemberUID: uid, fd: listenAt(t, path)})
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
		if !errors.Is(err, errClosed) {
			t.Errorf("Accept after Close: %v, want errClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept didn't end at Close")
	}
}

// Accept ends at its context, waiting for a connection and waiting for a
// hello that never comes; Close ends a hello in progress too.
func TestAcceptEndsAtContextAndClose(t *testing.T) {
	uid, _ := me(t)
	d := shortDir(t)
	path := filepath.Join(d, "x.sock")
	l, err := Listen(ListenConfig{Socket: path, MemberUID: uid, fd: listenAt(t, path)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accept := func(ctx context.Context) chan error {
		done := make(chan error, 1)
		go func() {
			_, err := l.Accept(ctx)
			done <- err
		}()
		return done
	}
	wait := func(done chan error, want error, what string) {
		t.Helper()
		select {
		case err := <-done:
			if !errors.Is(err, want) {
				t.Errorf("%s: %v, want %v", what, err, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: Accept didn't end", what)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := accept(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	wait(done, context.Canceled, "cancelled while waiting")

	// A client that connects and says nothing.
	silent := func() *os.File {
		f, err := connectUnix(context.Background(), path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	f := silent()
	defer f.Close()
	ctx, cancel = context.WithCancel(context.Background())
	done = accept(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()
	wait(done, context.Canceled, "cancelled during a hello")

	g := silent()
	defer g.Close()
	done = accept(context.Background())
	time.Sleep(100 * time.Millisecond)
	l.Close()
	wait(done, errClosed, "closed during a hello")
}

// A client beyond maxConns is told the channel is busy.
func TestAcceptBusy(t *testing.T) {
	uid, name := me(t)
	d := shortDir(t)
	path := filepath.Join(d, "b.sock")
	refused := make(chan error, 4)
	l, err := Listen(ListenConfig{Socket: path, MemberUID: uid, fd: listenAt(t, path), Version: "v1",
		groupsOf:  func(uint32, uint32) ([]string, error) { return nil, nil },
		peerNames: func([]uint32) ([]string, error) { return nil, nil },
		OnRefused: func(_ Op, err error) { refused <- err }})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var held []*ServerConn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	go func() {
		for {
			c, err := l.Accept(context.Background())
			if err != nil {
				return
			}
			_ = c.Accept()
			held = append(held, c) // kept open: each counts toward maxConns
		}
	}()
	var clients []*os.File
	defer func() {
		for _, f := range clients {
			f.Close()
		}
	}()
	for i := 0; i < maxConns; i++ {
		f, err := Dial(context.Background(), DialConfig{Pipe: path, Service: name, Op: OpStatus, Version: "v1", dirUID: &uid})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		clients = append(clients, f)
	}
	_, err = Dial(context.Background(), DialConfig{Pipe: path, Service: name, Op: OpStatus, Version: "v1", dirUID: &uid})
	if !errors.Is(err, ErrBusy) {
		t.Errorf("client %d: %v, want ErrBusy", maxConns+1, err)
	}
	if err := recv(t, refused); !errors.Is(err, ErrBusy) {
		t.Errorf("OnRefused got %v", err)
	}
}

// A full queue is retried until Dial's wait ends, then is ErrBusy; a
// context that ends first ends it.
func TestConnectFullQueue(t *testing.T) {
	d := shortDir(t)
	path := filepath.Join(d, "f.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	// Fill the queue: nobody accepts.
	var fill []*os.File
	defer func() {
		for _, f := range fill {
			f.Close()
		}
	}()
	for i := 0; i < 8; i++ {
		f, err := connectUnix(context.Background(), path, 10*time.Millisecond)
		if err != nil {
			break
		}
		fill = append(fill, f)
	}
	start := time.Now()
	if _, err := connectUnix(context.Background(), path, 200*time.Millisecond); !errors.Is(err, ErrBusy) {
		t.Fatalf("a full queue: %v, want ErrBusy", err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Error("a full queue wasn't retried until the wait ended")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := connectUnix(ctx, path, 10*time.Second); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a full queue with a context that ends: %v", err)
	}
}
