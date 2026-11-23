package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/channel"
	"github.com/vettid/vettid-agent/internal/pairing"
)

// testHost is a serviceHost on a state directory of the test's own, fed
// clients through clients.
type testHost struct {
	h       *serviceHost
	clients chan *hostConn
	done    chan error
	cancel  context.CancelFunc
}

func startHost(t *testing.T, idle time.Duration) *testHost {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	th := &testHost{
		h: &serviceHost{Dir: dir, AccessMinutes: 60, IdleStop: idle, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Protectors: &pairing.Protectors{NoPrompt: true, Dir: dir}},
		clients: make(chan *hostConn),
		done:    make(chan error, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	th.cancel = cancel
	go func() {
		th.done <- th.h.Serve(ctx, func(ctx context.Context) (*hostConn, error) {
			select {
			case c := <-th.clients:
				return c, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-th.done:
		case <-time.After(10 * time.Second):
			t.Error("the host did not stop")
		}
	})
	return th
}

// fakeClient is the client's end of one hostConn, and what the host
// answered its hello.
type fakeClient struct {
	net.Conn
	answer chan string // "accept", or the refusal's code
	closed chan struct{}
}

// connect hands the host a client asking for op.
func (th *testHost) connect(t *testing.T, op channel.Op) *fakeClient {
	t.Helper()
	server, client := net.Pipe()
	fc := &fakeClient{Conn: client, answer: make(chan string, 1), closed: make(chan struct{})}
	var once sync.Once
	closeS := func() error {
		once.Do(func() { close(fc.closed) })
		return server.Close()
	}
	c := &hostConn{rw: server, op: op,
		accept: func() error { fc.answer <- "accept"; return nil },
		refuse: func(err error) error {
			fc.answer <- err.Error()
			return closeS()
		},
		close: closeS,
	}
	select {
	case th.clients <- c:
	case <-time.After(5 * time.Second):
		t.Fatal("the host took no client")
	}
	t.Cleanup(func() { client.Close() })
	return fc
}

func (fc *fakeClient) waitAnswer(t *testing.T) string {
	t.Helper()
	select {
	case a := <-fc.answer:
		return a
	case <-time.After(5 * time.Second):
		t.Fatal("no answer to the hello")
		return ""
	}
}

// console reads the console exchange's lines until the exit code.
func (fc *fakeClient) console(t *testing.T) (string, int) {
	t.Helper()
	var out bytes.Buffer
	_ = fc.SetDeadline(time.Now().Add(10 * time.Second))
	code, err := channel.Relay(fc, &out)
	if err != nil {
		t.Fatalf("console: %v (so far %q)", err, out.String())
	}
	return out.String(), code
}

func (th *testHost) waitStopped(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case err := <-th.done:
		th.done <- err // for the cleanup
		return err
	case <-time.After(within):
		t.Fatalf("the host did not stop within %v", within)
		return nil
	}
}

func (th *testHost) running(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case err := <-th.done:
		th.done <- err
		t.Fatalf("the host stopped: %v", err)
	case <-time.After(d):
	}
}

// With nothing holding it, the host stops after its idle time.
func TestHostIdleStop(t *testing.T) {
	th := startHost(t, 150*time.Millisecond)
	start := time.Now()
	if err := th.waitStopped(t, 5*time.Second); !errors.Is(err, errIdle) {
		t.Fatalf("Serve = %v, want errIdle", err)
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Fatalf("stopped after %v", d)
	}
}

// A client holds the host; its idle time starts when the client leaves.
func TestHostClientHolds(t *testing.T) {
	th := startHost(t, 200*time.Millisecond)
	fc := th.connect(t, channel.OpMCP)
	if a := fc.waitAnswer(t); a != "accept" {
		t.Fatalf("hello: %s", a)
	}
	th.running(t, 600*time.Millisecond)
	if th.h.Held() != 1 {
		t.Fatalf("held %d", th.h.Held())
	}
	left := time.Now()
	fc.Close()
	if err := th.waitStopped(t, 5*time.Second); !errors.Is(err, errIdle) {
		t.Fatalf("Serve = %v, want errIdle", err)
	}
	if d := time.Since(left); d < 200*time.Millisecond {
		t.Fatalf("stopped %v after the client left, before its idle time", d)
	}
}

// The stop rule (AGENT-PLAN A3.10b, §4.9): what else holds the host (a
// run in flight, a run's answer still kept) keeps it running after the
// last client leaves; the idle time counts from its release.
func TestHostHoldOutlivesClient(t *testing.T) {
	th := startHost(t, 200*time.Millisecond)
	fc := th.connect(t, channel.OpMCP)
	fc.waitAnswer(t)
	th.h.Hold() // a run the stub started
	fc.Close()
	th.running(t, 700*time.Millisecond)
	released := time.Now()
	th.h.Release()
	if err := th.waitStopped(t, 5*time.Second); !errors.Is(err, errIdle) {
		t.Fatalf("Serve = %v, want errIdle", err)
	}
	if d := time.Since(released); d < 200*time.Millisecond {
		t.Fatalf("stopped %v after the release", d)
	}
}

// One stub at a time; pair and forget only while no stub is served, and
// no stub while they run.
func TestHostOneAtATime(t *testing.T) {
	th := startHost(t, time.Minute)
	first := th.connect(t, channel.OpMCP)
	if a := first.waitAnswer(t); a != "accept" {
		t.Fatalf("first: %s", a)
	}
	for _, op := range []channel.Op{channel.OpMCP, channel.OpPair, channel.OpForget} {
		fc := th.connect(t, op)
		if a := fc.waitAnswer(t); a != channel.ErrInUse.Error() {
			t.Fatalf("%s while a stub is served: %s, want in use", op, a)
		}
	}
	// status is answered meanwhile.
	st := th.connect(t, channel.OpStatus)
	if a := st.waitAnswer(t); a != "accept" {
		t.Fatalf("status: %s", a)
	}
	// The host answers only after the request line, as the client sends
	// it (net.Pipe is unbuffered: a host that answered first and closed
	// would fail this write).
	if err := channel.SendRequest(st, channel.Request{}); err != nil {
		t.Fatal(err)
	}
	if text, code := st.console(t); code != 0 || !strings.Contains(text, "Not paired") {
		t.Fatalf("status: %d %q", code, text)
	}
	first.Close()
	select {
	case <-first.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the host did not close the first stub's connection")
	}
	// forget holds the place: a stub is refused until it ends.
	fg := th.connect(t, channel.OpForget)
	if a := fg.waitAnswer(t); a != "accept" {
		t.Fatalf("forget: %s", a)
	}
	stub := th.connect(t, channel.OpMCP)
	if a := stub.waitAnswer(t); a != channel.ErrInUse.Error() {
		t.Fatalf("a stub while forget runs: %s, want in use", a)
	}
	if err := channel.SendRequest(fg, channel.Request{}); err != nil {
		t.Fatal(err)
	}
	if text, code := fg.console(t); code != 0 || !strings.Contains(text, "Nothing to forget") {
		t.Fatalf("forget: %d %q", code, text)
	}
}

// Without a finished pairing, a stub gets every tool answered
// not_paired, from the service.
func TestHostNotPaired(t *testing.T) {
	th := startHost(t, time.Minute)
	fc := th.connect(t, channel.OpMCP)
	fc.waitAnswer(t)
	_ = fc.SetDeadline(time.Now().Add(10 * time.Second))
	go func() { _, _ = io.WriteString(fc, msgInit+"\n"+msgCall+"\n") }()
	sc := bufio.NewScanner(fc)
	var answers []map[string]any
	for len(answers) < 2 && sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %q", sc.Text())
		}
		answers = append(answers, m)
	}
	if len(answers) != 2 {
		t.Fatalf("answers %v (%v)", answers, sc.Err())
	}
	res := answers[1]["result"].(map[string]any)
	sc2 := res["structuredContent"].(map[string]any)
	if res["isError"] != true || sc2["code"] != codeNotPaired || sc2["message"] != textNotPaired {
		t.Fatalf("tool answer %v", res)
	}
}

// pair reads the request once and never echoes the code; with a code
// that is not one, the pairing fails and says so.
func TestHostPairBadCode(t *testing.T) {
	th := startHost(t, time.Minute)
	fc := th.connect(t, channel.OpPair)
	fc.waitAnswer(t)
	const code = "not-a-pairing-code-1234"
	if err := channel.SendRequest(fc, channel.Request{Code: code, Label: "test"}); err != nil {
		t.Fatal(err)
	}
	text, rc := fc.console(t)
	if rc != 1 || text == "" {
		t.Fatalf("pair with a bad code: %d %q", rc, text)
	}
	if strings.Contains(text, code) {
		t.Fatalf("the answer echoes the code: %q", text)
	}
}

// consoleWriter sends each line as a text line, a last partial line at
// exit, then the code.
func TestConsoleWriter(t *testing.T) {
	var b bytes.Buffer
	w := &consoleWriter{w: &b}
	_, _ = io.WriteString(w, "one\ntw")
	_, _ = io.WriteString(w, "o\nthree")
	w.exit(3)
	var out bytes.Buffer
	code, err := channel.Relay(&b, &out)
	if err != nil || code != 3 || out.String() != "one\ntwo\nthree\n" {
		t.Fatalf("relay %d %v %q", code, err, out.String())
	}
}
