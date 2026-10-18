//go:build devstack

package devstack

// The dev stack (AGENT-PLAN §4.8, §9 rule 8): the tests use the stack
// that runs for VETTID_DEVSTACK_DATA, or start one from the vettid-vault
// checkout in VETTID_DEVSTACK_SRC, and stop it at the end only if they
// started it. One stack at a time: a stack is started only when none
// answers, only with 8 GB of memory available, and the tests of this
// package run one after the other (`go test -p 1`, no t.Parallel).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Environment of the dev-stack tests.
const (
	// envData is the stack's data directory (default: the user cache
	// directory's vettid-devstack, as cmd/devstack's -data).
	envData = "VETTID_DEVSTACK_DATA"
	// envSrc is a vettid-vault checkout to build and start a stack from
	// when none runs.
	envSrc = "VETTID_DEVSTACK_SRC"
	// envBin is a connector binary built with -tags devstack (default:
	// built by the tests).
	envBin = "VETTID_AGENT_BIN"
)

const (
	minAvailableGB = 8
	startTimeout   = 20 * time.Minute // the first start builds the stack's binaries
	stopTimeout    = 90 * time.Second
)

// Stack is a running dev stack, as its ready.json describes it.
type Stack struct {
	Data     string
	Ctl      string `json:"ctl"`
	API      string `json:"api"`
	RelayTLS string `json:"relay_tls"`
	RelayURL string `json:"relay_url"`
	Features string `json:"features"`
	PID      int    `json:"pid"`

	// proc is the stack this process started (nil: one that was
	// running, left running).
	proc *exec.Cmd
	done chan error
	log  *os.File
}

var (
	stackOnce sync.Once
	stackVal  *Stack
	stackErr  error
)

// TestMain stops the stack the tests started, if any.
func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	if stackVal != nil {
		if err := stackVal.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "devstack: stopping the dev stack: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

// devStack returns the dev stack, finding or starting it on first use.
// Dev-stack tests are skipped with -short (CI runs the package's unit
// tests that way).
func devStack(t *testing.T) *Stack {
	t.Helper()
	if testing.Short() {
		t.Skip("dev-stack test (-short)")
	}
	stackOnce.Do(func() { stackVal, stackErr = openStack(context.Background()) })
	if stackErr != nil {
		t.Fatalf("dev stack: %v", stackErr)
	}
	return stackVal
}

func dataDir() (string, error) {
	if d := os.Getenv(envData); d != "" {
		return filepath.Abs(d)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, "vettid-devstack"), nil
}

// openStack finds the stack that runs for the data directory, or starts
// one.
func openStack(ctx context.Context) (*Stack, error) {
	data, err := dataDir()
	if err != nil {
		return nil, err
	}
	if s, err := findStack(ctx, data); err == nil {
		fmt.Fprintf(os.Stderr, "devstack: using the dev stack that runs (pid %d, %s)\n", s.PID, data)
		return s, nil
	}
	src := os.Getenv(envSrc)
	if src == "" {
		return nil, fmt.Errorf("no dev stack answers for %s; start one (vettid-vault README, \"Local dev stack\"), or set %s to a vettid-vault checkout to start one", data, envSrc)
	}
	return startStack(ctx, data, src)
}

// readReady reads ready.json.
func readReady(data string) (*Stack, error) {
	b, err := os.ReadFile(filepath.Join(data, "run", "ready.json"))
	if err != nil {
		return nil, err
	}
	s := &Stack{Data: data}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("ready.json: %w", err)
	}
	if s.Ctl == "" || s.API == "" || s.RelayTLS == "" || s.PID <= 0 {
		return nil, errors.New("ready.json lacks ctl, api, relay_tls or pid")
	}
	return s, nil
}

// findStack returns the stack of ready.json if its process lives and
// its control port answers.
func findStack(ctx context.Context, data string) (*Stack, error) {
	s, err := readReady(data)
	if err != nil {
		return nil, err
	}
	if !alive(s.PID) {
		return nil, fmt.Errorf("pid %d is gone", s.PID)
	}
	if err := s.health(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func alive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func (s *Stack) health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.Ctl, "/")+"/dev/health", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("/dev/health: HTTP %d", resp.StatusCode)
	}
	return nil
}

// availableGB is MemAvailable (Linux), or -1 when unknown (the stack
// checks again itself: -wait-free-mem).
func availableGB() float64 {
	if runtime.GOOS != "linux" {
		return -1
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), ":"); ok && k == "MemAvailable" {
			kb, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 64)
			if err == nil {
				return kb / (1 << 20)
			}
		}
	}
	return -1
}

// startStack builds cmd/devstack from src into data and starts it.
func startStack(ctx context.Context, data, src string) (*Stack, error) {
	if gb := availableGB(); gb >= 0 && gb < minAvailableGB {
		return nil, fmt.Errorf("only %.1f GB of memory available; a dev stack needs %d (AGENT-PLAN §9 rule 8)", gb, minAvailableGB)
	}
	src, err := filepath.Abs(src)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	bin := filepath.Join(data, "devstack")
	fmt.Fprintf(os.Stderr, "devstack: building cmd/devstack from %s\n", src)
	build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-tags", "devenclave", "-o", bin, "./cmd/devstack")
	build.Dir = src
	build.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=readonly")
	if out, err := build.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("building cmd/devstack: %v\n%s", err, out)
	}
	_ = os.Remove(filepath.Join(data, "run", "ready.json"))
	logf, err := os.OpenFile(filepath.Join(data, "devstack-tests.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-data", data, "-src", src, "-wait-free-mem", strconv.Itoa(minAvailableGB))
	cmd.Stdout, cmd.Stderr = logf, logf
	setStackAttrs(cmd)
	fmt.Fprintf(os.Stderr, "devstack: starting the dev stack (log %s)\n", logf.Name())
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	started := &Stack{Data: data, proc: cmd, done: done, log: logf}
	deadline := time.Now().Add(startTimeout)
	for {
		select {
		case err := <-done:
			logf.Close()
			return nil, fmt.Errorf("the dev stack exited while starting (%v); see %s", err, logf.Name())
		case <-time.After(2 * time.Second):
		}
		if s, err := readReady(data); err == nil && s.PID == cmd.Process.Pid {
			if err := s.health(ctx); err == nil {
				s.proc, s.done, s.log = cmd, done, logf
				fmt.Fprintf(os.Stderr, "devstack: the dev stack is up (pid %d)\n", s.PID)
				return s, nil
			}
		}
		if time.Now().After(deadline) {
			_ = started.Close()
			return nil, fmt.Errorf("the dev stack did not get ready within %v; see %s", startTimeout, logf.Name())
		}
	}
}

// Close stops the stack if this process started it (SIGTERM: the stack
// tears its processes and LocalStack down) and waits until it is gone.
func (s *Stack) Close() error {
	if s.proc == nil {
		return nil
	}
	defer s.log.Close()
	_ = s.proc.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(stopTimeout):
		_ = s.proc.Process.Kill()
		<-s.done
		return fmt.Errorf("the dev stack did not stop within %v and was killed; check for its processes and LocalStack", stopTimeout)
	}
	if s.Ctl != "" && s.health(context.Background()) == nil {
		return errors.New("the dev stack's control port still answers after it stopped")
	}
	fmt.Fprintln(os.Stderr, "devstack: the dev stack stopped")
	return nil
}
