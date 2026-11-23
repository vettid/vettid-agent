//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/invite"
	"golang.org/x/sys/windows"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/mcp"
)

// otherUserEnv lets a test write under %ProgramData% as an elevated
// administrator; the Windows CI job's step for these tests sets it.
const otherUserEnv = "VETTID_AGENT_TEST_OTHER_USER"

func requireElevated(t *testing.T) {
	t.Helper()
	if os.Getenv(otherUserEnv) != "1" {
		t.Skipf("set %s=1 to write a pairing's configuration under ProgramData (CI only)", otherUserEnv)
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatalf("%s=1 needs an elevated (administrator) process", otherUserEnv)
	}
}

// installConfig writes pairing name's configuration file where ReadPipe
// looks, owned by Administrators, readable by Users; removed afterwards
// with any folder it made.
func installConfig(t *testing.T, name, pipe string) {
	t.Helper()
	path, err := channel.ConfigPath(name)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	var made []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		made = append(made, d)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Remove(path)
		for _, d := range made {
			os.Remove(d)
		}
	})
	if err := os.WriteFile(path, []byte(`{"pipe":"`+pipe+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, _ := sd.Owner()
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// An elevated administrator's `pair --name`, end to end: the real
// ReadPipe reads the admin-only configuration file (as an administrator,
// who could change it), the real Dial reaches a listener, the service's
// side sees an elevated administrator asking to pair and gets the code.
// Then the same command against a channel whose owner isn't the
// service's SID is refused before it sends anything.
func TestElevatedPairEndToEnd(t *testing.T) {
	requireElevated(t)
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	name := "ci-" + hex.EncodeToString(b[:4])
	pipe := "vettid-agent-" + name + "-" + hex.EncodeToString(b[4:])
	installConfig(t, name, pipe)
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := u.User.Sid.String()
	refused := make(chan error, 4)
	l, err := channel.Listen(channel.ListenConfig{Pipe: pipe, Owner: me, Member: me, Version: readVersion().Version,
		OnRefused: func(_ channel.Op, err error) { refused <- err }})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type served struct {
		c   *channel.ServerConn
		req channel.Request
		err error
	}
	got := make(chan served, 4)
	go func() {
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			_ = c.Accept()
			r, err := channel.ReadRequest(c)
			if err == nil {
				_ = channel.WriteText(c, "Paired as a test.")
				_ = channel.WriteExit(c, 0)
			}
			c.Close()
			got <- served{c, r, err}
		}
	}()

	// The listener is owned by this test's account, standing in for the
	// service's.
	oldService := stubService
	stubService = func(string) string { return me }
	var out, errOut bytes.Buffer
	v := newVault(t)
	theCode, err := v.Code(invite.KindAgent, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rc := run([]string{"pair", "--name", name, "--label", "CI", theCode}, &out, &errOut)
	stubService = oldService
	if rc != 0 || !strings.Contains(errOut.String(), "Paired as a test.") {
		t.Fatalf("elevated pair --name: exit %d, stderr %q", rc, errOut.String())
	}
	select {
	case s := <-got:
		if s.err != nil || s.c.Op != channel.OpPair || !s.c.Identity.ElevatedAdmin ||
			s.req != (channel.Request{Code: theCode, Label: "CI"}) {
			t.Fatalf("the service's side: op %q identity %+v request %+v, %v", s.c.Op, s.c.Identity, s.req, s.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the service's side got nothing")
	}

	// With the real expected owner, NT SERVICE\vettid-agent-<name>, this
	// listener (owned by the test's account) is not the service: refused
	// before any byte, and said as "not running".
	errOut.Reset()
	if rc := run([]string{"pair", "--name", name, theCode}, &out, &errOut); rc != 1 || !strings.Contains(errOut.String(), mcp.NoService().Text) {
		t.Fatalf("pair against a channel that isn't the service's: exit %d, stderr %q", rc, errOut.String())
	}
	select {
	case err := <-refused:
		t.Logf("the impostor's side saw: %v (no hello)", err)
	case s := <-got:
		t.Fatalf("the impostor got a request: %+v", s.req)
	case <-time.After(5 * time.Second):
		t.Fatal("the impostor's side saw nothing")
	}
}
