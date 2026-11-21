package channel

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TrustedInstaller's SID is fixed and published; it checks the
// derivation of a virtual service account's SID from its name.
func TestServiceSIDTrustedInstaller(t *testing.T) {
	const want = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	for _, name := range []string{"TrustedInstaller", "trustedinstaller", "TRUSTEDINSTALLER"} {
		if got := ServiceSID(name); got != want {
			t.Errorf("ServiceSID(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestAdmit(t *testing.T) {
	member := Identity{Member: true}
	admin := Identity{ElevatedAdmin: true, HoldsAdmins: true}
	both := Identity{Member: true, ElevatedAdmin: true, HoldsAdmins: true} // the member, elevated
	memberAdmin := Identity{Member: true, HoldsAdmins: true}               // the member, an administrator not elevated
	nobody := Identity{}
	cases := []struct {
		op   Op
		id   Identity
		want bool
	}{
		{OpMCP, member, true},
		{OpMCP, admin, false},       // an administrator who is not the member: no tools
		{OpMCP, both, false},        // a member who is an administrator: no tools
		{OpMCP, memberAdmin, false}, // also with Administrators deny-only
		{OpStatus, memberAdmin, true},
		{OpPair, memberAdmin, false},
		{OpForget, both, true},
		{OpMCP, nobody, false},
		{OpStatus, member, true},
		{OpStatus, admin, true},
		{OpStatus, nobody, false},
		{OpPair, member, false}, // the member's normal process: never pair
		{OpPair, admin, true},
		{OpPair, both, true},
		{OpForget, member, false},
		{OpForget, admin, true},
		{OpForget, nobody, false},
		{Op("share"), both, false},
		{Op(""), both, false},
	}
	for _, c := range cases {
		err := Admit(c.op, c.id)
		if (err == nil) != c.want {
			t.Errorf("Admit(%q, %+v) = %v, want allowed %v", c.op, c.id, err, c.want)
		}
		wantErr := ErrNotAllowed
		if c.op == OpMCP && c.id.Member && c.id.HoldsAdmins {
			wantErr = ErrMemberIsAdmin
		}
		if err != nil && !errors.Is(err, wantErr) {
			t.Errorf("Admit(%q, %+v) = %v, want %v", c.op, c.id, err, wantErr)
		}
	}
}

// The account names of A3.10a (8): the first 8 hexadecimal digits of the
// SHA-256 of the pairing's name (printf work | sha256sum).
func TestAccountNames(t *testing.T) {
	if got := AccountHash("work"); got != "00e13ed7" {
		t.Errorf("AccountHash(work) = %s", got)
	}
	if got := AccountHash("a"); got != "ca978112" {
		t.Errorf("AccountHash(a) = %s", got)
	}
	for got, want := range map[string]string{
		ConnectorUser("work"): "vettid-c-00e13ed7",
		RunnerUser("work", 1): "vettid-r-00e13ed7-1",
		RunnerUser("work", 2): "vettid-r-00e13ed7-2",
		MemberGroup("work"):   "vettid-m-00e13ed7",
	} {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

func TestNames(t *testing.T) {
	for _, n := range []string{"a", "work", "claude-1", "0", strings.Repeat("a", 32)} {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false", n)
		}
	}
	for _, n := range []string{"", "-a", "A", "a_b", "a.b", "a b", `a\b`, "a/b", strings.Repeat("a", 33), "é"} {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
	r := strings.Repeat("0a", 16)
	if !validPipe("work", "vettid-agent-work-"+r) {
		t.Error("a valid pipe name refused")
	}
	for _, p := range []string{"vettid-agent-other-" + r, "vettid-agent-work-" + r + "0", "vettid-agent-work-" + strings.ToUpper(r), "x" + "vettid-agent-work-" + r} {
		if validPipe("work", p) {
			t.Errorf("validPipe(work, %q) = true", p)
		}
	}
}

// hello runs a client's and a server's hello over an in-memory pipe.
func hello(t *testing.T, op Op, clientV, serverV string) (clientErr, serverErr error, gotOp Op) {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	type res struct {
		op  Op
		err error
	}
	done := make(chan res, 1)
	go func() {
		op, err := readClientHello(s, serverV)
		if err == nil {
			err = accept(s, serverV)
		}
		done <- res{op, err}
	}()
	clientErr = clientHandshake(c, op, clientV)
	r := <-done
	return clientErr, r.err, r.op
}

func TestHello(t *testing.T) {
	if cerr, serr, op := hello(t, OpMCP, "v1.2.3", "v1.2.3"); cerr != nil || serr != nil || op != OpMCP {
		t.Fatalf("same versions: client %v, server %v, op %q", cerr, serr, op)
	}
	// Each end refuses the other's version.
	cerr, serr, _ := hello(t, OpMCP, "v1.2.3", "v1.2.4")
	if !errors.Is(cerr, ErrVersionsDiffer) || !errors.Is(serr, ErrVersionsDiffer) {
		t.Fatalf("versions differ: client %v, server %v", cerr, serr)
	}
	// An unknown operation is refused by the server.
	cerr, serr, _ = hello(t, Op("share"), "v1", "v1")
	if !errors.Is(cerr, ErrBadHello) || !errors.Is(serr, ErrBadHello) {
		t.Fatalf("unknown op: client %v, server %v", cerr, serr)
	}
}

// The client also refuses a server that accepts a hello of another
// version: the check is made at both ends.
func TestHelloClientChecksServerVersion(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		_, _ = readLine(s)
		_ = accept(s, "v9")
	}()
	if err := clientHandshake(c, OpMCP, "v1"); !errors.Is(err, ErrVersionsDiffer) {
		t.Fatalf("client accepted a server of another version: %v", err)
	}
}

func TestServerHelloRefusals(t *testing.T) {
	for _, in := range []string{
		"not json\n",
		`{"vettid_channel":2,"op":"mcp","version":"v1"}` + "\n",
		`{"vettid_channel":1,"op":"mcp","version":"v1","path":"C:\\x"}` + "\n", // nothing else is taken
		strings.Repeat("x", maxHello+10) + "\n",
		"",
	} {
		c, s := net.Pipe()
		go func() {
			_, _ = io.WriteString(c, in)
			c.Close()
		}()
		_ = s.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := readClientHello(s, "v1"); err == nil {
			t.Errorf("hello %.40q accepted", in)
		}
		c.Close()
		s.Close()
	}
}

// The hello reads nothing past its line: the operation's bytes after it
// are left for the operation.
func TestHelloLeavesTheRest(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	go func() {
		_, _ = io.WriteString(c, `{"vettid_channel":1,"op":"mcp","version":"v1"}`+"\n"+`{"jsonrpc":"2.0"}`+"\n")
	}()
	if _, err := readClientHello(s, "v1"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(s).ReadString('\n')
	if err != nil || line != `{"jsonrpc":"2.0"}`+"\n" {
		t.Fatalf("after the hello: %q, %v", line, err)
	}
}
