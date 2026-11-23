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
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
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
			Protectors: serviceProtectors(dir)},
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
		close:       closeS,
		setDeadline: server.SetDeadline,
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
	second := th.connect(t, channel.OpMCP)
	if a := second.waitAnswer(t); a != channel.ErrInUse.Error() {
		t.Fatalf("a second stub: %s, want in use", a)
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
}

// An administrator's forget (or pair) comes before the member's agent:
// the stub's session is ended, then forget runs, and no stub is taken
// until it has.
func TestHostAdminPreemptsStub(t *testing.T) {
	th := startHost(t, time.Minute)
	first := th.connect(t, channel.OpMCP)
	if a := first.waitAnswer(t); a != "accept" {
		t.Fatalf("stub: %s", a)
	}
	fg := th.connect(t, channel.OpForget)
	if a := fg.waitAnswer(t); a != "accept" {
		t.Fatalf("forget while a stub is served: %s, want accept", a)
	}
	select {
	case <-first.closed:
	default:
		t.Fatal("forget was accepted before the stub's session ended")
	}
	stub := th.connect(t, channel.OpMCP)
	if a := stub.waitAnswer(t); a != channel.ErrInUse.Error() {
		t.Fatalf("a stub while forget runs: %s, want in use", a)
	}
	pr := th.connect(t, channel.OpPair)
	if a := pr.waitAnswer(t); a != channel.ErrInUse.Error() {
		t.Fatalf("pair while forget runs: %s, want in use", a)
	}
	if err := channel.SendRequest(fg, channel.Request{}); err != nil {
		t.Fatal(err)
	}
	if text, code := fg.console(t); code != 0 || !strings.Contains(text, "Nothing to forget") {
		t.Fatalf("forget: %d %q", code, text)
	}
	// Then, once forget's connection is closed, a stub is served again.
	select {
	case <-fg.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("forget's connection was not closed")
	}
	again := th.connect(t, channel.OpMCP)
	if a := again.waitAnswer(t); a != "accept" {
		t.Fatalf("a stub after forget: %s", a)
	}
}

// A status client that never sends its request is closed after
// requestWait, and gives its hold back.
func TestHostSilentStatusClosed(t *testing.T) {
	old := requestWait
	requestWait = 200 * time.Millisecond
	t.Cleanup(func() { requestWait = old })
	th := startHost(t, time.Minute)
	st := th.connect(t, channel.OpStatus)
	st.waitAnswer(t)
	select {
	case <-st.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("a silent status client was not closed")
	}
	for end := time.Now().Add(5 * time.Second); th.h.Held() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("held %d after the silent client was closed", th.h.Held())
		}
	}
}

// Clients that say nothing, or don't read their answers, don't keep the
// host from stopping: on stop it closes them. (requestWait is long here,
// so the close, not the deadline, is what ends them.)
func TestHostStopClosesClients(t *testing.T) {
	old := requestWait
	requestWait = time.Hour
	t.Cleanup(func() { requestWait = old })
	th := startHost(t, time.Minute)
	st := th.connect(t, channel.OpStatus)
	st.waitAnswer(t)
	fg := th.connect(t, channel.OpForget)
	fg.waitAnswer(t)
	stub := th.connect(t, channel.OpMCP)
	stub.waitAnswer(t) // in use (forget holds the place): refused and closed
	th.cancel()
	start := time.Now()
	if err := th.waitStopped(t, 10*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v", err)
	}
	t.Logf("stopped in %v with silent clients", time.Since(start))
	for _, c := range []*fakeClient{st, fg} {
		select {
		case <-c.closed:
		default:
			t.Fatal("a client was left open")
		}
	}
}

// A stub that sends but never reads its answers doesn't keep the host
// from stopping either (the not-paired path goes through stopSession).
func TestHostStopNonReadingStub(t *testing.T) {
	th := startHost(t, time.Minute)
	stub := th.connect(t, channel.OpMCP)
	stub.waitAnswer(t)
	go func() {
		for i := 0; i < 50; i++ {
			if _, err := io.WriteString(stub, msgCall+"\n"); err != nil {
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	th.cancel()
	if err := th.waitStopped(t, 15*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v", err)
	}
}

// A client handed over just as the idle timer fires is served, not
// dropped; the host stops once it has left.
func TestHostIdleRaceServesClient(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	h := &serviceHost{Dir: dir, IdleStop: 100 * time.Millisecond, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Protectors: serviceProtectors(dir)}
	server, client := net.Pipe()
	defer client.Close()
	answered := make(chan string, 1)
	var once sync.Once
	done := make(chan error, 1)
	go func() {
		done <- h.Serve(context.Background(), func(ctx context.Context) (*hostConn, error) {
			// The channel had admitted a client when the stop began: it is
			// handed over after accept's context ended.
			<-ctx.Done()
			var c *hostConn
			once.Do(func() {
				c = &hostConn{rw: server, op: channel.OpStatus,
					accept:      func() error { answered <- "accept"; return nil },
					refuse:      func(err error) error { answered <- err.Error(); return server.Close() },
					close:       server.Close,
					setDeadline: server.SetDeadline}
			})
			if c == nil {
				return nil, ctx.Err()
			}
			return c, nil
		})
	}()
	select {
	case a := <-answered:
		if a != "accept" {
			t.Fatalf("answer %s", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client handed over at the stop was dropped")
	}
	if err := channel.SendRequest(client, channel.Request{}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code, err := channel.Relay(client, &out); err != nil || code != 0 {
		t.Fatalf("status: %d %v %q", code, err, out.String())
	}
	select {
	case err := <-done:
		if !errors.Is(err, errIdle) {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the host did not stop after the client left")
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

// readerFunc is an io.Reader from a function.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// pair's request deadline is lifted once the request is read: a pairing
// that takes longer than requestWait still answers.
func TestHostPairOutlivesRequestDeadline(t *testing.T) {
	old := requestWait
	requestWait = 200 * time.Millisecond
	t.Cleanup(func() { requestWait = old })
	th := startHost(t, time.Minute)
	th.h.pairOptions = func(o *pairing.Options) {
		code := o.Code
		o.Code = func() (string, error) {
			time.Sleep(600 * time.Millisecond) // the pairing waits past requestWait
			return code()
		}
	}
	fc := th.connect(t, channel.OpPair)
	fc.waitAnswer(t)
	if err := channel.SendRequest(fc, channel.Request{Code: "not-a-pairing-code-1234"}); err != nil {
		t.Fatal(err)
	}
	if text, rc := fc.console(t); rc != 1 || text == "" {
		t.Fatalf("pair: %d %q", rc, text)
	}
}

// During the idle stop's drain, a client handed over is served, and the
// host goes back to taking clients: a second one is served too.
func TestHostDrainTakesClientsAgain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	h := &serviceHost{Dir: dir, IdleStop: 100 * time.Millisecond, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Protectors: serviceProtectors(dir)}
	type end struct {
		c      *hostConn
		client net.Conn
		answer chan string
	}
	mk := func() end {
		server, client := net.Pipe()
		e := end{client: client, answer: make(chan string, 1)}
		e.c = &hostConn{rw: server, op: channel.OpStatus,
			accept:      func() error { e.answer <- "accept"; return nil },
			refuse:      func(err error) error { e.answer <- err.Error(); return server.Close() },
			close:       server.Close,
			setDeadline: server.SetDeadline}
		t.Cleanup(func() { client.Close() })
		return e
	}
	first, second := mk(), mk()
	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- h.Serve(context.Background(), func(ctx context.Context) (*hostConn, error) {
			if calls == 1 && ctx.Err() != nil {
				// The stop's accept has ended: the second client waits for
				// the host to take clients again, as it would on the channel.
				return nil, ctx.Err()
			}
			calls++
			switch calls {
			case 1:
				// Handed over as the stop began.
				<-ctx.Done()
				return first.c, nil
			case 2:
				// Connects during the drain, once the host takes clients again.
				return second.c, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	for _, e := range []end{first, second} {
		select {
		case a := <-e.answer:
			if a != "accept" {
				t.Fatalf("answer %s", a)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a client was not served")
		}
	}
	for _, e := range []end{first, second} {
		if err := channel.SendRequest(e.client, channel.Request{}); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if code, err := channel.Relay(e.client, &out); err != nil || code != 0 {
			t.Fatalf("status: %d %v", code, err)
		}
	}
	select {
	case err := <-done:
		if !errors.Is(err, errIdle) {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the host did not stop")
	}
}

// The decrypted record's device and grants are cleared once a stub's
// session has ended.
func TestHostClearsRecordAfterSession(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	pairOptions = nil
	var rec *pairing.Record
	var device []byte
	h := &serviceHost{Dir: dir, IdleStop: time.Minute, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Protectors: serviceProtectors(dir),
		resolve:    func(string) state.Protector { return cmdTestProtector{} },
		runSessionFn: func(_ context.Context, s session) error {
			rec = s.Record
			device = rec.Device
			if len(device) == 0 || bytes.Count(device, []byte{0}) == len(device) {
				t.Error("the session got no device")
			}
			return nil
		}}
	th := &testHost{h: h, clients: make(chan *hostConn), done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	th.cancel = cancel
	go func() {
		th.done <- h.Serve(ctx, func(ctx context.Context) (*hostConn, error) {
			select {
			case c := <-th.clients:
				return c, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}()
	t.Cleanup(func() { cancel(); <-th.done })
	fc := th.connect(t, channel.OpMCP)
	fc.waitAnswer(t)
	select {
	case <-fc.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not end")
	}
	if rec == nil {
		t.Fatal("no session ran")
	}
	if bytes.Count(device, []byte{0}) != len(device) {
		t.Fatal("the record's device was not cleared after the session")
	}
	if len(rec.Leash) > 0 && bytes.Count(rec.Leash, []byte{0}) != len(rec.Leash) {
		t.Fatal("the record's grants were not cleared after the session")
	}
}

// An administrator's forget ends a not-paired stub that never reads its
// answers: the not-paired path goes through stopSession, not only
// through closeAll at the host's stop.
func TestHostPreemptsNonReadingStub(t *testing.T) {
	oldStop, oldPre := mcpStopWait, preemptWait
	mcpStopWait, preemptWait = 100*time.Millisecond, 3*time.Second
	t.Cleanup(func() { mcpStopWait, preemptWait = oldStop, oldPre })
	th := startHost(t, time.Minute)
	stub := th.connect(t, channel.OpMCP)
	stub.waitAnswer(t)
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := io.WriteString(stub, msgCall+"\n"); err != nil {
				return
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	fg := th.connect(t, channel.OpForget)
	if a := fg.waitAnswer(t); a != "accept" {
		t.Fatalf("forget with a non-reading stub: %s, want accept", a)
	}
}

// A forget client that never sends its request is closed after
// requestWait, and gives its place back: a stub is served again.
func TestHostSilentForgetClosed(t *testing.T) {
	old := requestWait
	requestWait = 200 * time.Millisecond
	t.Cleanup(func() { requestWait = old })
	th := startHost(t, time.Minute)
	fg := th.connect(t, channel.OpForget)
	if a := fg.waitAnswer(t); a != "accept" {
		t.Fatalf("forget: %s", a)
	}
	select {
	case <-fg.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("a silent forget client was not closed")
	}
	stub := th.connect(t, channel.OpMCP)
	if a := stub.waitAnswer(t); a != "accept" {
		t.Fatalf("a stub after the silent forget: %s", a)
	}
}

// A record that is not paired is cleared by loadRecord before it says
// not paired.
func TestHostLoadRecordClearsUnpaired(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	device := []byte(`{"name":"agent","vault_id":"v1","device_id":"d1"}`)
	raw, err := (&pairing.Record{Phase: pairing.PhaseWaiting, Deadline: time.Now().Add(time.Hour), Device: device}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(cmdTestProtector{}, raw); err != nil {
		t.Fatal(err)
	}
	var seen *pairing.Record
	h := &serviceHost{Dir: dir, store: store, resolve: func(string) state.Protector { return cmdTestProtector{} },
		Protectors: serviceProtectors(dir)}
	hostDecoded = func(r *pairing.Record) { seen = r }
	t.Cleanup(func() { hostDecoded = nil })
	defer store.Close()
	if _, err := h.loadRecord(); !errors.Is(err, vaultconn.ErrNotPaired) {
		t.Fatalf("loadRecord = %v, want not paired", err)
	}
	if seen == nil || len(seen.Device) == 0 {
		t.Fatal("no record was decoded")
	}
	if bytes.Count(seen.Device, []byte{0}) != len(seen.Device) {
		t.Fatalf("the record that is not paired was left in memory: %q", seen.Device)
	}
}

// A client handed over after the host closed its clients is closed at
// once, never served.
func TestHostTrackAfterCloseAll(t *testing.T) {
	h := &serviceHost{}
	h.closeAll()
	if h.track(&hostConn{}) {
		t.Fatal("a client was tracked after closeAll")
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

// The service has no passphrase source: its protectors must say so, or
// pairing takes descriptor 0 for --passphrase-fd and refuses the platform
// protector (on every platform a service runs on).
func TestServiceProtectorsHaveNoPassphraseSource(t *testing.T) {
	p := serviceProtectors(t.TempDir())
	if p.Source.FD != -1 || p.Source.File != "" || p.Pass != nil {
		t.Fatalf("the service's protectors name a passphrase source: FD %d, file %q, passphrase set %v", p.Source.FD, p.Source.File, p.Pass != nil)
	}
	if !p.NoPrompt {
		t.Error("the service's protectors may prompt on a terminal")
	}
}
