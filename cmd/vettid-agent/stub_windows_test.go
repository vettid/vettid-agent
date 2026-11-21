//go:build windows

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/mcp"
)

// The stub against a real channel (a pipe this test's user owns, standing
// in for the service's): it is admitted as the member, for MCP, and the
// messages pass unchanged both ways.
func TestStubOverPipe(t *testing.T) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := u.User.Sid.String()
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	pipe := "vettid-agent-work-" + hex.EncodeToString(b)
	l, err := channel.Listen(channel.ListenConfig{Pipe: pipe, Owner: me, Member: me, Version: readVersion().Version})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	oldRead, oldService, oldIn := stubReadPipe, stubService, mcpIn
	stubReadPipe = func(string) (string, error) { return pipe, nil }
	stubService = func(string) string { return me }
	t.Cleanup(func() { stubReadPipe, stubService, mcpIn = oldRead, oldService, oldIn })

	// The stub holds no key or state: with every folder a state could be
	// in made unreadable for this user, it still passes MCP messages.
	denied := t.TempDir()
	if out, err := exec.Command("icacls", denied, "/deny", "*"+me+":(OI)(CI)F").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("icacls", denied, "/remove:d", "*"+me).Run() })
	if _, err := os.ReadDir(denied); err == nil {
		// An elevated administrator reads past a deny entry (backup
		// semantics); the unreadable case is the normal user's run.
		if !windows.GetCurrentProcessToken().IsElevated() {
			t.Fatal("the denied folder can still be read")
		}
		t.Log("elevated: the denied folder stays readable; the unreadable case runs as a normal user")
	}
	for _, v := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "TEMP", "TMP"} {
		t.Setenv(v, denied)
	}

	inR, inW := io.Pipe()
	mcpIn = inR
	var out, errOut syncBuffer
	done := make(chan int, 1)
	go func() { done <- run([]string{"mcp", "--name", "work"}, &out, &errOut) }()

	if holdsAdministrators(t) {
		// A member who is an administrator (the CI runner's account):
		// the service refuses tools, and the stub answers every tool
		// with member_is_admin, end to end.
		actx, acancel := context.WithCancel(context.Background())
		defer acancel()
		go func() {
			for {
				c, err := l.Accept(actx)
				if err != nil {
					return
				}
				c.Close()
				t.Error("the service admitted an administrator member for tools")
			}
		}()
		go func() { _, _ = io.WriteString(inW, msgInit+"\n"+msgCall+"\n") }()
		for end := time.Now().Add(10 * time.Second); strings.Count(out.String(), "\n") < 2; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("stdout %q, stderr %q", out.String(), errOut.String())
			}
		}
		if !strings.Contains(out.String(), `"code":"`+mcp.CodeMemberIsAdmin+`"`) {
			t.Fatalf("stdout %q", out.String())
		}
		inW.Close()
		if rc := <-done; rc != 1 {
			t.Fatalf("exit %d", rc)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := l.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v (stub: %s)", err, errOut.String())
	}
	defer c.Close()
	if c.Op != channel.OpMCP || !c.Identity.Member {
		t.Fatalf("server saw %q %+v", c.Op, c.Identity)
	}
	if err := c.Accept(); err != nil {
		t.Fatal(err)
	}
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	go func() { _, _ = io.WriteString(inW, req) }()
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || got != req {
		t.Fatalf("service read %q, %v", got, err)
	}
	ans := `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}` + "\n"
	if _, err := io.WriteString(c, ans); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(5 * time.Second); out.String() != ans; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("stdout %q", out.String())
		}
	}
	inW.Close()
	select {
	case rc := <-done:
		if rc != 0 || out.String() != ans {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out.String(), errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stub did not exit when the client closed standard input")
	}
}

// holdsAdministrators: this test's token holds Administrators, enabled
// or deny-only.
func holdsAdministrators(t *testing.T) bool {
	t.Helper()
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups.AllGroups() {
		if g.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return true
		}
	}
	return false
}
