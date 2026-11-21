package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/mcp"
)

const stubPipe = "vettid-agent-work-0123456789abcdef0123456789abcdef"

// fakeService stands in for the channel: Dial returns one end of an
// in-memory pipe, whose other end the test drives as the service.
type fakeService struct {
	mu      sync.Mutex
	cfgs    []channel.DialConfig
	ends    chan net.Conn
	dialErr error
	pipeErr error
}

func withFakeService(t *testing.T) *fakeService {
	t.Helper()
	f := &fakeService{ends: make(chan net.Conn, 4)}
	oldRead, oldDial, oldIn := stubReadPipe, stubDial, mcpIn
	stubReadPipe = func(n string) (string, error) {
		if f.pipeErr != nil {
			return "", f.pipeErr
		}
		return stubPipe, nil
	}
	stubDial = func(ctx context.Context, cfg channel.DialConfig) (io.ReadWriteCloser, error) {
		f.mu.Lock()
		f.cfgs = append(f.cfgs, cfg)
		f.mu.Unlock()
		if f.dialErr != nil {
			return nil, f.dialErr
		}
		c, s := net.Pipe()
		f.ends <- s
		return c, nil
	}
	t.Cleanup(func() { stubReadPipe, stubDial, mcpIn = oldRead, oldDial, oldIn })
	return f
}

func (f *fakeService) end(t *testing.T) net.Conn {
	t.Helper()
	select {
	case s := <-f.ends:
		t.Cleanup(func() { s.Close() })
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("the stub did not dial")
		return nil
	}
}

// The stub dials the pairing's channel for MCP, with the service's SID
// derived from the name, and passes MCP messages both ways unchanged:
// standard output holds exactly what the service sent, and nothing
// else. It holds no state: there is no state directory at all here. It
// exits 0, closing the channel, when the client closes standard input.
func TestStubPassesMessages(t *testing.T) {
	f := withFakeService(t)
	inR, inW := io.Pipe()
	mcpIn = inR
	var out, errOut syncBuffer
	done := make(chan int, 1)
	go func() { done <- run([]string{"mcp", "--name", "work"}, &out, &errOut) }()
	s := f.end(t)
	cfg := f.cfgs[0]
	if cfg.Op != channel.OpMCP || cfg.Pipe != stubPipe || cfg.Service != channel.ServiceSID("vettid-agent-work") ||
		cfg.Version != readVersion().Version {
		t.Fatalf("dial config %+v", cfg)
	}
	req := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"leash.list_available","arguments":{}}}` + "\n"
	ans := `{"jsonrpc":"2.0","id":1,"result":{"x":"\u00e9 é"}}` + "\n" + `{"jsonrpc":"2.0","id":2,"result":{}}` + "\n"
	go func() { _, _ = io.WriteString(inW, req) }()
	got := make([]byte, len(req))
	if _, err := io.ReadFull(s, got); err != nil || string(got) != req {
		t.Fatalf("the service read %q, %v", got, err)
	}
	if _, err := io.WriteString(s, ans); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(5 * time.Second); out.String() != ans; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("stdout %q, want %q", out.String(), ans)
		}
	}
	inW.Close()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("exit %d: %s", rc, errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stub did not exit when the client closed standard input")
	}
	// The channel is closed.
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Read(make([]byte, 1)); err == nil {
		t.Fatal("the channel stays open")
	}
	if out.String() != ans {
		t.Fatalf("stdout %q", out.String())
	}
}

// When the service closes the channel, the stub exits 1 and says so on
// standard error only.
func TestStubServiceCloses(t *testing.T) {
	f := withFakeService(t)
	inR, _ := io.Pipe()
	mcpIn = inR
	var out, errOut syncBuffer
	done := make(chan int, 1)
	go func() { done <- run([]string{"mcp", "--name", "work"}, &out, &errOut) }()
	f.end(t).Close()
	select {
	case rc := <-done:
		if rc != 1 || out.String() != "" || !strings.Contains(errOut.String(), "closed the channel") {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out.String(), errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stub did not exit")
	}
}

// mcpSession runs the stub with the given messages on standard input and
// returns its answers, one per line.
func mcpSession(t *testing.T, args []string, msgs ...string) (rc int, answers []map[string]any, stdout, stderr string) {
	t.Helper()
	mcpIn = strings.NewReader(strings.Join(msgs, "\n") + "\n")
	var out, errOut bytes.Buffer
	rc = run(args, &out, &errOut)
	sc := bufio.NewScanner(bytes.NewReader(out.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("stdout holds a line that is not JSON: %q", sc.Text())
		}
		answers = append(answers, m)
	}
	return rc, answers, out.String(), errOut.String()
}

const (
	msgInit = `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	msgList = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	msgCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"leash.list_available","arguments":{}}}`
)

// Without its service the stub answers MCP itself: every tool with "No
// service" (or "Versions differ"), the text on standard error once, and
// never the connector in its own process.
func TestStubWithoutService(t *testing.T) {
	cases := []struct {
		name             string
		pipeErr, dialErr error
		code, text       string
		stderr           string
	}{
		{"no configuration", fmt.Errorf("%w: no file", channel.ErrNoService), nil, mcp.CodeServiceNotRunning, mcp.NoService().Text, ""},
		{"no channel", nil, channel.ErrNoService, mcp.CodeServiceNotRunning, mcp.NoService().Text, ""},
		{"squatted", nil, channel.ErrNotService, mcp.CodeServiceNotRunning, mcp.NoService().Text, ""},
		{"another user", nil, channel.ErrNotAllowed, mcp.CodeServiceNotRunning, mcp.NoService().Text, TextNotThisAccount},
		{"versions differ", nil, channel.ErrVersionsDiffer, mcp.CodeVersionsDiffer, mcp.TextVersionsDiffer, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := withFakeService(t)
			f.pipeErr, f.dialErr = c.pipeErr, c.dialErr
			rc, ans, _, errOut := mcpSession(t, []string{"mcp", "--name", "work"}, msgInit, msgList, msgCall)
			if rc != 1 || len(ans) != 3 {
				t.Fatalf("exit %d, %d answers, stderr %q", rc, len(ans), errOut)
			}
			tools := ans[1]["result"].(map[string]any)["tools"].([]any)
			if len(tools) != 5 {
				t.Fatalf("tools/list: %v", ans[1])
			}
			res := ans[2]["result"].(map[string]any)
			sc := res["structuredContent"].(map[string]any)
			if res["isError"] != true || sc["code"] != c.code || sc["message"] != c.text {
				t.Fatalf("tool answer %v", res)
			}
			if strings.Count(errOut, c.text) != 1 || !strings.Contains(errOut, c.stderr) {
				t.Fatalf("stderr %q", errOut)
			}
		})
	}
}

// A second stub on the pairing: the service refuses it as in use; the
// stub exits 1 with the same words as the connector in the agent's
// account, and writes nothing to standard output.
func TestStubInUse(t *testing.T) {
	f := withFakeService(t)
	f.dialErr = channel.ErrInUse
	rc, _, out, errOut := mcpSession(t, []string{"mcp", "--name", "work"}, msgInit)
	if rc != 1 || out != "" || !strings.Contains(errOut, "in use by another agent app") {
		t.Fatalf("exit %d, stdout %q, stderr %q", rc, out, errOut)
	}
}

// The stub takes the pairing's name and --verbose only: no path, no
// state directory, no protector, and --run-path or --run-env with their
// own text.
func TestStubFlags(t *testing.T) {
	f := withFakeService(t)
	for _, args := range [][]string{
		{"mcp", "--name", "work", "--run-path", `C:\tools`},
		{"mcp", "--run-env=PATH", "--name=work"},
		{"mcp", "-name", "work", "-run-path=x"},
	} {
		rc, _, out, errOut := mcpSession(t, args)
		if rc != 2 || out != "" || !strings.Contains(errOut, TextStubRunFlags) {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, rc, out, errOut)
		}
	}
	for _, args := range [][]string{
		{"mcp", "--name", "work", "--state-dir", t.TempDir()},
		{"mcp", "--name", "work", "--passphrase-file", "x"},
		{"mcp", "--name", "work", "--access-minutes", "5"},
		{"mcp", "--name", "work", "extra"},
		{"mcp", "--name", "Work"},
		{"mcp", "--name", `..\x`},
	} {
		rc, _, out, errOut := mcpSession(t, args)
		if rc != 2 || out != "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, rc, out, errOut)
		}
	}
	if len(f.cfgs) != 0 {
		t.Fatalf("a refused command dialed: %+v", f.cfgs)
	}
}

// pair, status and forget with --name dial for their operation, send
// their request and show the service's answer, with its exit code.
func TestChannelCommands(t *testing.T) {
	type served struct {
		req channel.Request
		err error
	}
	serve := func(f *fakeService, t *testing.T, text string, exit int) <-chan served {
		ch := make(chan served, 1)
		go func() {
			s := <-f.ends
			defer s.Close()
			r, err := channel.ReadRequest(s)
			if err == nil {
				_ = channel.WriteText(s, text)
				_ = channel.WriteExit(s, exit)
			}
			ch <- served{r, err}
		}()
		return ch
	}
	t.Run("status", func(t *testing.T) {
		f := withFakeService(t)
		got := serve(f, t, "Paired: yes", 0)
		var out, errOut bytes.Buffer
		if rc := run([]string{"status", "--name", "work"}, &out, &errOut); rc != 0 || out.String() != "Paired: yes\n" {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out.String(), errOut.String())
		}
		if r := <-got; r.err != nil || r.req != (channel.Request{}) || f.cfgs[0].Op != channel.OpStatus {
			t.Fatalf("service got %+v, op %q", r, f.cfgs[0].Op)
		}
	})
	t.Run("pair", func(t *testing.T) {
		f := withFakeService(t)
		got := serve(f, t, "Approve on your phone", 3)
		oldIn := codeIn
		codeIn = strings.NewReader("THE-CODE")
		t.Cleanup(func() { codeIn = oldIn })
		var out, errOut bytes.Buffer
		rc := run([]string{"pair", "--name", "work", "--label", "Build box", "--restart"}, &out, &errOut)
		if rc != 3 || out.Len() != 0 || !strings.Contains(errOut.String(), "Approve on your phone\n") {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out.String(), errOut.String())
		}
		r := <-got
		if r.err != nil || r.req != (channel.Request{Code: "THE-CODE", Label: "Build box", Restart: true}) || f.cfgs[0].Op != channel.OpPair {
			t.Fatalf("service got %+v, op %q", r, f.cfgs[0].Op)
		}
		if strings.Contains(errOut.String(), "THE-CODE") {
			t.Fatal("the code was shown")
		}
	})
	t.Run("forget", func(t *testing.T) {
		f := withFakeService(t)
		got := serve(f, t, "Forgotten", 0)
		var out, errOut bytes.Buffer
		if rc := run([]string{"forget", "--name", "work"}, &out, &errOut); rc != 0 || out.String() != "Forgotten\n" {
			t.Fatalf("exit %d, stdout %q, stderr %q", rc, out.String(), errOut.String())
		}
		if r := <-got; r.err != nil || f.cfgs[0].Op != channel.OpForget {
			t.Fatalf("service got %+v", r)
		}
	})
	// Refusals: pair and forget from a process that isn't an elevated
	// administrator, and a service of another version.
	for _, c := range []struct {
		args []string
		err  error
		want string
	}{
		{[]string{"pair", "--name", "work", "CODE"}, channel.ErrNotAllowed, TextNeedsAdmin},
		{[]string{"forget", "--name", "work"}, channel.ErrNotAllowed, TextNeedsAdmin},
		{[]string{"status", "--name", "work"}, channel.ErrNotAllowed, TextNotThisAccount},
		{[]string{"status", "--name", "work"}, channel.ErrVersionsDiffer, mcp.TextVersionsDiffer},
		{[]string{"status", "--name", "work"}, channel.ErrNoService, mcp.NoService().Text},
		{[]string{"pair", "--name", "work", "CODE"}, channel.ErrNotService, mcp.NoService().Text},
	} {
		f := withFakeService(t)
		f.dialErr = c.err
		var out, errOut bytes.Buffer
		if rc := run(c.args, &out, &errOut); rc != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), c.want) {
			t.Errorf("%v with %v: exit %d, stdout %q, stderr %q", c.args, c.err, rc, out.String(), errOut.String())
		}
	}
	// A service that leaves without an exit code is a failure.
	f := withFakeService(t)
	go func() {
		s := <-f.ends
		_, _ = channel.ReadRequest(s)
		_ = channel.WriteText(s, "half")
		s.Close()
	}()
	var out, errOut bytes.Buffer
	if rc := run([]string{"status", "--name", "work"}, &out, &errOut); rc != 1 || !strings.Contains(errOut.String(), channel.ErrNoAnswer.Error()) {
		t.Fatalf("exit %d, stderr %q", rc, errOut.String())
	}
}
