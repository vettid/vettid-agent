//go:build devstack

package devstack

// The connector under test: the vettid-agent binary built with the
// devstack tag, run as the operator runs `pair` and `status`, and as an
// MCP client runs `mcp` (the MCP Go SDK's client over its standard input
// and output), with VETTID_AGENT_DEVSTACK naming the stack's control
// port.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vettid/vettid-agent/internal/state"
)

// testPassphrase protects the test connectors' keys (TEST-ONLY; the
// passphrase protector, so that no TPM is needed).
const testPassphrase = "Devstack-Test-Passphrase-1, not a secret"

var (
	binOnce sync.Once
	binPath string
	binErr  error
	// binDir is the directory the tests built the connector in (removed
	// by TestMain).
	binDir string
)

// agentBinary builds the connector with the devstack tag once (or takes
// VETTID_AGENT_BIN).
func agentBinary(t *testing.T) string {
	t.Helper()
	binOnce.Do(func() {
		if b := os.Getenv(envBin); b != "" {
			binPath, binErr = filepath.Abs(b)
			return
		}
		dir, err := os.MkdirTemp("", "vettid-agent-devstack-")
		if err != nil {
			binErr = err
			return
		}
		binDir, binPath = dir, filepath.Join(dir, "vettid-agent")
		out, err := exec.Command("go", "build", "-p", "1", "-tags", "devstack", "-o", binPath, "github.com/vettid/vettid-agent/cmd/vettid-agent").CombinedOutput()
		if err != nil {
			binErr = fmt.Errorf("building the connector: %v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

// Agent is one connector: a state directory and its passphrase file.
type Agent struct {
	t        *testing.T
	s        *Stack
	bin      string
	Dir      string
	passFile string
}

func newAgent(t *testing.T, s *Stack) *Agent {
	t.Helper()
	tmp := t.TempDir()
	a := &Agent{t: t, s: s, bin: agentBinary(t), Dir: filepath.Join(tmp, "state"), passFile: filepath.Join(tmp, "passphrase")}
	if err := os.WriteFile(a.passFile, []byte(testPassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *Agent) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, a.bin, args...)
	cmd.Env = append(os.Environ(), EnvControl+"="+a.s.Ctl)
	return cmd
}

// lines collects a process's standard error, line by line.
type lines struct {
	mu   sync.Mutex
	all  []string
	more chan struct{}
}

func newLines() *lines { return &lines{more: make(chan struct{}, 1)} }

func (l *lines) add(s string) {
	l.mu.Lock()
	l.all = append(l.all, s)
	l.mu.Unlock()
	select {
	case l.more <- struct{}{}:
	default:
	}
}

func (l *lines) Write(p []byte) (int, error) {
	for _, s := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		l.add(s)
	}
	return len(p), nil
}

func (l *lines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.all, "\n")
}

// wait waits for a line that re matches and returns its submatches.
func (l *lines) wait(re *regexp.Regexp, timeout time.Duration) ([]string, bool) {
	return l.waitOr(re, nil, timeout)
}

// waitOr is wait that also gives up once stop is closed (the process
// exited) and no line matches.
func (l *lines) waitOr(re *regexp.Regexp, stop <-chan struct{}, timeout time.Duration) ([]string, bool) {
	end := time.After(timeout)
	stopped := false
	for {
		l.mu.Lock()
		for _, s := range l.all {
			if m := re.FindStringSubmatch(s); m != nil {
				l.mu.Unlock()
				return m, true
			}
		}
		l.mu.Unlock()
		if stopped {
			return nil, false
		}
		select {
		case <-l.more:
		case <-stop:
			stopped, stop = true, nil
		case <-end:
			return nil, false
		}
	}
}

// Pairing is a running `vettid-agent pair`.
type Pairing struct {
	cmd    *exec.Cmd
	stderr *lines
	done   chan struct{}
	err    error
}

var sasLine = regexp.MustCompile(`same code: (\d{3}) (\d{3})\.`)

// pair starts `vettid-agent pair` with the code on the command line.
func (a *Agent) pair(ctx context.Context, code string) *Pairing {
	a.t.Helper()
	cmd := a.command(ctx, "pair", "--state-dir", a.Dir, "--passphrase", "--passphrase-file", a.passFile,
		"--name", "devstack test agent", code)
	p := &Pairing{cmd: cmd, stderr: newLines(), done: make(chan struct{})}
	pr, err := cmd.StderrPipe()
	if err != nil {
		a.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		a.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			p.stderr.add(sc.Text())
		}
		p.err = cmd.Wait()
		close(p.done)
	}()
	a.t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

// sas waits for the SAS the connector shows and returns its six digits.
func (p *Pairing) sas(t *testing.T) string {
	t.Helper()
	m, ok := p.stderr.waitOr(sasLine, p.done, 2*time.Minute)
	if !ok {
		t.Fatalf("pair showed no SAS:\n%s", p.stderr)
	}
	return m[1] + m[2]
}

// wait waits for `pair` to exit and returns its exit code and standard
// error.
func (p *Pairing) wait(t *testing.T) (int, string) {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(3 * time.Minute):
		t.Fatalf("pair did not exit:\n%s", p.stderr)
	}
	code := 0
	var ee *exec.ExitError
	if errors.As(p.err, &ee) {
		code = ee.ExitCode()
	} else if p.err != nil {
		t.Fatalf("pair: %v", p.err)
	}
	return code, p.stderr.String()
}

// status runs `vettid-agent status` and returns its standard output.
func (a *Agent) status(ctx context.Context) string {
	a.t.Helper()
	cmd := a.command(ctx, "status", "--state-dir", a.Dir, "--passphrase-file", a.passFile)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		a.t.Fatalf("status: %v: %s", err, errb.String())
	}
	return out.String()
}

// assertWiped checks that the state file is gone (after an unlink).
func (a *Agent) assertWiped() {
	a.t.Helper()
	p := filepath.Join(a.Dir, state.StateFileName)
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		a.t.Errorf("the state file is still there after the unlink (%v)", err)
	}
}

// MCP is a running `vettid-agent mcp` with the SDK's client session.
type MCP struct {
	t      *testing.T
	cmd    *exec.Cmd
	cs     *sdk.ClientSession
	Stderr *lines
	closed bool
}

// mcp starts `vettid-agent mcp --verbose` (message types and ids on
// standard error) and connects the MCP Go SDK's client to it.
func (a *Agent) mcp(ctx context.Context, extra ...string) *MCP {
	a.t.Helper()
	args := append([]string{"mcp", "--state-dir", a.Dir, "--passphrase-file", a.passFile, "--verbose"}, extra...)
	cmd := a.command(context.Background(), args...)
	m := &MCP{t: a.t, cmd: cmd, Stderr: newLines()}
	cmd.Stderr = m.Stderr
	client := sdk.NewClient(&sdk.Implementation{Name: "devstack-test", Version: "1"}, nil)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cs, err := client.Connect(cctx, &sdk.CommandTransport{Command: cmd, TerminateDuration: 30 * time.Second}, nil)
	if err != nil {
		a.t.Fatalf("connecting to vettid-agent mcp: %v\n%s", err, m.Stderr)
	}
	m.cs = cs
	a.t.Cleanup(func() { m.close() })
	return m
}

// close ends the MCP session (closes the connector's standard input)
// and returns the connector's exit code.
func (m *MCP) close() int {
	if !m.closed {
		m.closed = true
		_ = m.cs.Close()
	}
	if m.cmd.ProcessState == nil {
		return -1
	}
	return m.cmd.ProcessState.ExitCode()
}

// call calls a tool and returns its structured content and isError.
func (m *MCP) call(ctx context.Context, name string, args map[string]any) (map[string]any, bool) {
	m.t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if args == nil {
		args = map[string]any{}
	}
	res, err := m.cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		m.t.Fatalf("%s: %v\nconnector log:\n%s", name, err, m.Stderr)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		m.t.Fatalf("%s: structured content: %v", name, err)
	}
	return out, res.IsError
}

// info calls leash.connection_info.
func (m *MCP) info(ctx context.Context) map[string]any {
	m.t.Helper()
	out, isErr := m.call(ctx, "leash.connection_info", nil)
	if isErr {
		m.t.Fatalf("leash.connection_info: %v", out)
	}
	return out
}

// waitInfo polls leash.connection_info until ok accepts it.
func (m *MCP) waitInfo(ctx context.Context, what string, ok func(map[string]any) bool, timeout time.Duration) map[string]any {
	m.t.Helper()
	end := time.Now().Add(timeout)
	for {
		in := m.info(ctx)
		if ok(in) {
			return in
		}
		if time.Now().After(end) {
			m.t.Fatalf("connection_info: not %s within %v: %v", what, timeout, in)
		}
		time.Sleep(time.Second)
	}
}

// code returns a tool result's code ("" for status ok).
func code(out map[string]any) string {
	if s, _ := out["status"].(string); s == "ok" {
		return ""
	}
	if s, _ := out["status"].(string); s == "pending" {
		return "pending"
	}
	c, _ := out["code"].(string)
	return c
}
