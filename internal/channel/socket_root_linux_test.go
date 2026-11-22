//go:build linux

package channel

// Root tests of the Unix-socket end (AGENT-PLAN §6 A5.6's tests: "the
// socket refuses another user and a stub refuses a link or a server of
// another owner"; "pair from the member's normal process speaking the
// protocol directly is refused"; "a root caller that is not the member
// gets no tool answers"). They run only as root with
// VETTID_TEST_LINUX_ROOT=1, on a Linux VM or the ubuntu CI runner:
// throwaway users and groups, the test binary copied to a root-owned
// folder, and a transient systemd socket unit made with the same
// settings as the real one (AGENT-LINUX-RUNTIME §3). Everything made is
// removed in cleanup when a test fails, though not when the test binary
// is killed or times out (Go runs no cleanup then): on a reused machine,
// remove any vtm*, vto* and vettid-c-* users and vettid-agent-t* units
// left by such a run (vti* too).

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const roleVar = "VETTID_TEST_CHANNEL_ROLE"

// TestRootHelperServer is the service's side, started by systemd as the
// connector's account: it takes the activated socket and tells each
// admitted client who it is.
func TestRootHelperServer(t *testing.T) {
	if os.Getenv(roleVar) != "server" {
		t.Skip("a helper process of TestRootChannel")
	}
	uid, _ := strconv.ParseUint(os.Getenv("VETTID_TEST_MEMBER_UID"), 10, 32)
	l, err := Listen(ListenConfig{Socket: os.Getenv("VETTID_TEST_SOCKET"), MemberUID: uint32(uid), Version: "test"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(3)
	}
	for {
		c, err := l.Accept(context.Background())
		if err != nil {
			os.Exit(4)
		}
		_ = c.Accept()
		fmt.Fprintf(c, "member=%v admin=%v holds=%v\n", c.Identity.Member, c.Identity.ElevatedAdmin, c.Identity.HoldsAdmins)
		// Kept open until the client leaves, so held clients count.
		go func() { _, _ = io.Copy(io.Discard, c); c.Close() }()
	}
}

// TestRootHelperFlood fills the channel as the member: maxConns clients
// admitted and held, then maxConns silent ones. It prints "ready" and
// waits until its standard input closes.
func TestRootHelperFlood(t *testing.T) {
	if os.Getenv(roleVar) != "flood" {
		t.Skip("a helper process of TestRootChannel")
	}
	path, service := os.Getenv("VETTID_TEST_SOCKET"), os.Getenv("VETTID_TEST_SERVICE")
	var held []*os.File
	for i := 0; i < maxConns; i++ {
		f, err := Dial(context.Background(), DialConfig{Pipe: path, Service: service, Op: OpStatus, Version: "test"})
		if err != nil {
			fmt.Println("dial:", err)
			os.Exit(3)
		}
		held = append(held, f)
	}
	for i := 0; i < maxConns; i++ {
		f, err := connectUnix(context.Background(), path, time.Second)
		if err != nil {
			fmt.Println("connect:", err)
			os.Exit(3)
		}
		held = append(held, f)
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	for _, f := range held {
		f.Close()
	}
}

// TestRootHelperClient is a client run as another user: it dials and
// prints "result" and what it got.
func TestRootHelperClient(t *testing.T) {
	if os.Getenv(roleVar) != "client" {
		t.Skip("a helper process of TestRootChannel")
	}
	fmt.Println("result", dialResult(os.Getenv("VETTID_TEST_SOCKET"), os.Getenv("VETTID_TEST_SERVICE"), Op(os.Getenv("VETTID_TEST_OP"))))
}

// TestRootHelperListener listens on a socket as whatever user runs it,
// for a server of another uid: it prints "ready" and waits.
func TestRootHelperListener(t *testing.T) {
	if os.Getenv(roleVar) != "listener" {
		t.Skip("a helper process of TestRootChannel")
	}
	l, err := net.Listen("unix", os.Getenv("VETTID_TEST_SOCKET"))
	if err != nil {
		fmt.Println("listen:", err)
		os.Exit(3)
	}
	fmt.Println("ready")
	for {
		c, err := l.Accept()
		if err != nil {
			os.Exit(0)
		}
		// Answer like a service would, so only the uid check can refuse.
		go func() { _ = accept(c, "test"); time.Sleep(time.Second); c.Close() }()
	}
}

// dialResult dials and names the outcome: "ok <what the server said>",
// or the error's name.
func dialResult(path, service string, op Op) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f, err := Dial(ctx, DialConfig{Pipe: path, Service: service, Op: op, Version: "test"})
	if err != nil {
		for _, e := range []struct {
			err  error
			name string
		}{
			{ErrNoService, "no_service"}, {ErrNotService, "not_service"}, {ErrAccessDenied, "access_denied"},
			{ErrNotAllowed, "not_allowed"}, {ErrMemberIsAdmin, "member_is_admin"}, {ErrVersionsDiffer, "versions_differ"},
			{ErrBadHello, "bad_hello"}, {ErrBusy, "busy"},
		} {
			if errors.Is(err, e.err) {
				return e.name
			}
		}
		return "other: " + err.Error()
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	return "ok " + strings.TrimSpace(line)
}

type rootEnv struct {
	t        *testing.T
	name     string // the pairing
	bin      string // the test binary, in a root-owned folder
	sock     string
	conn     string // the connector's account
	member   string
	other    string
	intruder string // in the member group, but not the member
	unit     string
	memberID uint32
}

func randHex(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func (e *rootEnv) cmd(args ...string) string {
	e.t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		e.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// later runs a cleanup step, reporting a failure without stopping the
// others.
func (e *rootEnv) later(args ...string) {
	e.t.Cleanup(func() {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			e.t.Errorf("cleanup %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	})
}

func uidOf(t *testing.T, name string) (uint32, uint32, []uint32) {
	t.Helper()
	u, err := user.Lookup(name)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	ids, err := u.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	var groups []uint32
	for _, id := range ids {
		g, _ := strconv.ParseUint(id, 10, 32)
		groups = append(groups, uint32(g))
	}
	return uint32(uid), uint32(gid), groups
}

// as runs the test binary as user, in role, with vars, and returns its
// output.
func (e *rootEnv) as(name, role string, vars ...string) *exec.Cmd {
	return e.asWith(name, nil, nil, role, vars...)
}

// asWith is as, with the primary group replaced (gid, as newgrp would)
// and more supplementary groups held (extra) than the group database
// lists.
func (e *rootEnv) asWith(name string, gidOver *uint32, extra []uint32, role string, vars ...string) *exec.Cmd {
	uid, gid, groups := uidOf(e.t, name)
	if gidOver != nil {
		gid = *gidOver
	}
	groups = append(groups, extra...)
	c := exec.Command(e.bin, "-test.run=^TestRootHelper", "-test.count=1", "-test.v")
	c.Env = append([]string{"PATH=/usr/bin:/bin", roleVar + "=" + role}, vars...)
	c.Dir = "/"
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups}}
	return c
}

// clientAs dials as user and returns its result.
func (e *rootEnv) clientAs(name string, op Op) string {
	e.t.Helper()
	return e.clientWith(name, nil, nil, op)
}

func (e *rootEnv) clientWith(name string, gid *uint32, extra []uint32, op Op) string {
	e.t.Helper()
	out, err := e.asWith(name, gid, extra, "client", "VETTID_TEST_SOCKET="+e.sock, "VETTID_TEST_SERVICE="+e.conn, "VETTID_TEST_OP="+string(op)).CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		if r, ok := strings.CutPrefix(l, "result "); ok {
			return r
		}
	}
	e.t.Fatalf("client as %s: %v\n%s", name, err, out)
	return ""
}

func setupRoot(t *testing.T) *rootEnv {
	if os.Getenv("VETTID_TEST_LINUX_ROOT") != "1" || os.Geteuid() != 0 {
		t.Skip("root tests: run as root with VETTID_TEST_LINUX_ROOT=1")
	}
	r := randHex(t, 3)
	e := &rootEnv{t: t, name: "t" + r}
	e.conn, e.member, e.other, e.intruder = ConnectorUser(e.name), "vtm"+r, "vto"+r, "vti"+r
	e.sock, e.unit = SocketPath(e.name), "vettid-agent-"+e.name
	group := MemberGroup(e.name)

	for _, u := range []string{e.conn, e.member, e.other, e.intruder} {
		args := []string{"useradd", "--no-create-home", "--shell", "/usr/sbin/nologin", "--user-group"}
		if u == e.conn {
			args = append(args, "--system")
		}
		e.cmd(append(args, u)...)
		e.later("userdel", u)
	}
	e.cmd("groupadd", "--system", group)
	e.later("groupdel", group)
	e.cmd("gpasswd", "-a", e.member, group)
	e.cmd("gpasswd", "-a", e.intruder, group)
	e.memberID, _, _ = uidOf(t, e.member)

	// The test binary, where the connector's account and the clients can
	// run it.
	dir := "/usr/local/libexec/vettid-test-" + r
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	e.bin = filepath.Join(dir, "channel.test")
	dst, err := os.OpenFile(e.bin, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	dst.Close()

	// The socket unit, as A5.6's (AGENT-LINUX-RUNTIME §3).
	t.Cleanup(func() {
		os.Remove(e.sock)
		_ = os.Remove(SocketDir) // only when empty: never a real pairing's
	})
	// A transient unit that stopped cleanly is gone already; reset-failed
	// is for one that didn't, so its error is not a failure.
	t.Cleanup(func() { _ = exec.Command("systemctl", "reset-failed", e.unit+".service", e.unit+".socket").Run() })
	e.later("systemctl", "stop", e.unit+".socket", e.unit+".service")
	e.cmd("systemd-run", "--unit="+e.unit,
		"--socket-property=ListenStream="+e.sock,
		"--socket-property=SocketUser="+e.conn,
		"--socket-property=SocketGroup="+group,
		"--socket-property=SocketMode=0660",
		"--socket-property=DirectoryMode=0755",
		"--socket-property=RemoveOnStop=yes",
		"-p", "User="+e.conn, "-p", "Group="+e.conn,
		"-E", roleVar+"=server",
		"-E", "VETTID_TEST_MEMBER_UID="+strconv.FormatUint(uint64(e.memberID), 10),
		"-E", "VETTID_TEST_SOCKET="+e.sock,
		e.bin, "-test.run=^TestRootHelperServer$", "-test.count=1")
	return e
}

func TestRootChannel(t *testing.T) {
	e := setupRoot(t)
	want := map[string]string{
		"member mcp":    "ok member=true admin=false holds=false",
		"member status": "ok member=true admin=false holds=false",
		"member pair":   "not_allowed", // the member's normal process speaking the protocol
		"member forget": "not_allowed",
		"other mcp":     "access_denied", // the socket's mode keeps another user out
		"other status":  "access_denied",
		// Another user who could open the socket (put in the member group
		// by mistake) is dropped before its hello: no answer at all.
		"intruder status": "bad_hello",
	}
	got := map[string]string{
		"member mcp":      e.clientAs(e.member, OpMCP),
		"member status":   e.clientAs(e.member, OpStatus),
		"member pair":     e.clientAs(e.member, OpPair),
		"member forget":   e.clientAs(e.member, OpForget),
		"other mcp":       e.clientAs(e.other, OpMCP),
		"other status":    e.clientAs(e.other, OpStatus),
		"intruder status": e.clientAs(e.intruder, OpStatus),
	}
	// Root (a command under sudo): pair, forget and status, never tools.
	for _, op := range []Op{OpStatus, OpPair, OpForget} {
		want["root "+string(op)] = "ok member=false admin=true holds=false"
		got["root "+string(op)] = dialResult(e.sock, e.conn, op)
	}
	want["root mcp"] = "not_allowed"
	got["root mcp"] = dialResult(e.sock, e.conn, OpMCP)
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %q, want %q", k, got[k], w)
		}
	}

	// The socket systemd made is what the clients check for.
	var st syscall.Stat_t
	if err := syscall.Lstat(e.sock, &st); err != nil {
		t.Fatal(err)
	}
	connUID, _, _ := uidOf(t, e.conn)
	if st.Uid != connUID || st.Mode&0o777 != 0o660 {
		t.Errorf("the socket: uid %d mode %o", st.Uid, st.Mode&0o777)
	}
}

// A member in a root-equivalent group gets member_is_admin for tools,
// and status still. A member in sudo keeps its tools (AGENT-LINUX-RUNTIME
// §11): with MemberAdmin false, root code found no sudo rule that asks
// for no password.
func TestRootMemberIsAdmin(t *testing.T) {
	e := setupRoot(t)
	if _, err := user.LookupGroup("sudo"); err == nil {
		e.cmd("gpasswd", "-a", e.member, "sudo")
		e.later("gpasswd", "-d", e.member, "sudo")
		if got := e.clientAs(e.member, OpMCP); got != "ok member=true admin=false holds=false" {
			t.Errorf("a member in sudo, tools: %q, want its tools", got)
		}
	} else {
		t.Log("no sudo group here; the sudo case is not checked")
	}
	if _, err := user.LookupGroup("disk"); err != nil {
		t.Skip("no disk group here")
	}
	e.cmd("gpasswd", "-a", e.member, "disk")
	e.later("gpasswd", "-d", e.member, "disk")
	if got := e.clientAs(e.member, OpMCP); got != "member_is_admin" {
		t.Errorf("a member in disk, tools: %q", got)
	}
	if got := e.clientAs(e.member, OpStatus); got != "ok member=true admin=false holds=true" {
		t.Errorf("a member in disk, status: %q", got)
	}
}

// A group the client holds counts though the group database doesn't
// list the member in it: as a supplementary group (SO_PEERGROUPS), and
// as the primary group of the process (newgrp's, SO_PEERCRED's gid).
func TestRootHeldAdminGroup(t *testing.T) {
	e := setupRoot(t)
	g, err := user.LookupGroup("disk")
	if err != nil {
		t.Skip("no disk group here")
	}
	gid, _ := strconv.ParseUint(g.Gid, 10, 32)
	disk := uint32(gid)
	if got := e.clientWith(e.member, nil, nil, OpMCP); got != "ok member=true admin=false holds=false" {
		t.Fatalf("the member, not in disk: %q", got)
	}
	if got := e.clientWith(e.member, nil, []uint32{disk}, OpMCP); got != "member_is_admin" {
		t.Errorf("disk held as a supplementary group: %q, want member_is_admin", got)
	}
	if got := e.clientWith(e.member, &disk, nil, OpMCP); got != "member_is_admin" {
		t.Errorf("disk as the process's primary group: %q, want member_is_admin", got)
	}
}

// The client refuses a link, a socket of another owner, and a server of
// another uid, before sending anything.
func TestRootClientRefusesImpostors(t *testing.T) {
	e := setupRoot(t)
	// Start the real service, so the folder exists and holds the socket.
	if got := dialResult(e.sock, e.conn, OpStatus); !strings.HasPrefix(got, "ok") {
		t.Fatalf("the service: %q", got)
	}
	connUID, _, _ := uidOf(t, e.conn)
	otherUID, otherGID, _ := uidOf(t, e.other)

	// A link to the real socket.
	link := filepath.Join(SocketDir, e.name+"-link.sock")
	if err := os.Symlink(e.sock, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(link) })
	if got := dialResult(link, e.conn, OpStatus); got != "not_service" {
		t.Errorf("a link: %q, want not_service", got)
	}

	// A socket owned by another user, in the right folder.
	squat := filepath.Join(SocketDir, e.name+"-squat.sock")
	l, err := net.Listen("unix", squat)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); os.Remove(squat) })
	if err := os.Chown(squat, int(otherUID), int(otherGID)); err != nil {
		t.Fatal(err)
	}
	if got := dialResult(squat, e.conn, OpStatus); got != "not_service" {
		t.Errorf("a socket of another owner: %q, want not_service", got)
	}

	// A link to the socket's folder, in a root-owned folder: every
	// folder in the chain must be one, not a link to one.
	linkDir := "/run/vtl" + randHex(t, 3)
	if err := os.Symlink(SocketDir, linkDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(linkDir) })
	if got := dialResult(filepath.Join(linkDir, e.name+".sock"), e.conn, OpStatus); got != "not_service" {
		t.Errorf("a linked folder: %q, want not_service", got)
	}

	// A good folder under one other users can change (/tmp): every
	// folder up to / counts.
	under := "/tmp/vtw" + randHex(t, 3)
	if err := os.Mkdir(under, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(under) })
	deep := filepath.Join(under, "s.sock")
	dl, err := net.Listen("unix", deep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dl.Close() })
	if err := os.Chown(deep, int(connUID), -1); err != nil {
		t.Fatal(err)
	}
	if got := dialResult(deep, e.conn, OpStatus); got != "not_service" {
		t.Errorf("a folder under /tmp: %q, want not_service", got)
	}

	// A socket owned by the connector's account but listened on by
	// another user: only the server's uid gives it away.
	tmp := "/run/vettid-test-" + randHex(t, 3)
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	if err := os.Chown(tmp, int(otherUID), int(otherGID)); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(tmp, "s.sock")
	lc := e.as(e.other, "listener", "VETTID_TEST_SOCKET="+inner)
	out, err := lc.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := lc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lc.Process.Kill(); lc.Wait() })
	ready := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			if s.Text() == "ready" {
				ready <- true
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("the other user's listener didn't start")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the other user's listener didn't start")
	}
	moved := filepath.Join(SocketDir, e.name+"-other.sock")
	if err := os.Rename(inner, moved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(moved) })
	if err := os.Chown(moved, int(connUID), -1); err != nil {
		t.Fatal(err)
	}
	if got := dialResult(moved, e.conn, OpStatus); got != "not_service" {
		t.Errorf("a server of another uid: %q, want not_service", got)
	}
}

// Root's elevated commands get through while the member holds every
// place the channel has (maxConns admitted, maxConns more silent).
func TestRootNotStarved(t *testing.T) {
	e := setupRoot(t)
	fl := e.as(e.member, "flood", "VETTID_TEST_SOCKET="+e.sock, "VETTID_TEST_SERVICE="+e.conn)
	in, err := fl.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := fl.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := fl.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); fl.Process.Kill(); fl.Wait() })
	ready := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			if l := s.Text(); l == "ready" || strings.HasPrefix(l, "dial:") || strings.HasPrefix(l, "connect:") {
				ready <- l
				return
			}
		}
		ready <- "ended"
	}()
	select {
	case l := <-ready:
		if l != "ready" {
			t.Fatalf("the member's flood: %s", l)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the member's flood didn't start")
	}
	// One more member client is past twice maxConns: dropped unanswered.
	if got := e.clientAs(e.member, OpStatus); got != "bad_hello" {
		t.Errorf("one more member client behind the flood: %q, want bad_hello", got)
	}
	start := time.Now()
	if got := dialResult(e.sock, e.conn, OpStatus); got != "ok member=false admin=true holds=false" {
		t.Errorf("root's status behind the member's flood: %q", got)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("root waited %v behind the flood", time.Since(start))
	}
}
