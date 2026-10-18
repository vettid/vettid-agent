package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/leash/request"
	"github.com/vettid/vettid-agent/internal/pairing/pairtest"
	"github.com/vettid/vettid-agent/internal/state"
	"github.com/vettid/vettid-agent/internal/vaultconn"
)

// pairedDir pairs through `vettid-agent pair` and returns the state
// directory.
func pairedDir(t *testing.T, v *pairtest.Vault) string {
	t.Helper()
	code, err := v.Code(invite.KindAgent, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "state")
	withTestPairing(t, v, "")
	var errOut bytes.Buffer
	if rc := run([]string{"pair", "--state-dir", dir, code}, &bytes.Buffer{}, &errOut); rc != 0 {
		t.Fatalf("pair: %d %s", rc, errOut.String())
	}
	return dir
}

func withTestMCP(t *testing.T, v *pairtest.Vault, stdin io.Reader) {
	t.Helper()
	mcpIn = stdin
	mcpResolve = func(string) state.Protector { return cmdTestProtector{} }
	mcpOptions = func(o *vaultconn.Options) {
		o.HTTP = v.HTTPClient()
		o.PollWait = 10 * time.Millisecond
	}
	t.Cleanup(func() { mcpIn, mcpResolve, mcpOptions = os.Stdin, nil, nil })
}

// TestMCPExitsOnEOF: `mcp` connects, and exits 0 when standard input
// closes; it writes nothing to standard output.
func TestMCPExitsOnEOF(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	pr, pw := io.Pipe()
	withTestMCP(t, v, pr)
	done := make(chan int, 1)
	var out, errOut bytes.Buffer
	go func() { done <- run([]string{"mcp", "--state-dir", dir}, &out, &errOut) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(strings.Join(v.Received(), ","), "vault.status") {
		if time.Now().After(deadline) {
			t.Fatal("no vault.status")
		}
		time.Sleep(10 * time.Millisecond)
	}
	pw.Close()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("exit %d: %s", rc, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mcp did not exit on EOF")
	}
	if out.Len() != 0 {
		t.Errorf("wrote to standard output: %q", out.String())
	}
}

// TestMCPUnlinked: device.unlinked wipes the state and `mcp` exits 1
// with the AG12 text; standard output stays empty.
func TestMCPUnlinked(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	if _, err := v.SendEvent("device.unlinked", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	pr, pw := io.Pipe()
	defer pw.Close()
	withTestMCP(t, v, pr)
	var out, errOut bytes.Buffer
	if rc := run([]string{"mcp", "--state-dir", dir}, &out, &errOut); rc != 1 {
		t.Fatalf("exit %d: %s", rc, errOut.String())
	}
	if !strings.Contains(errOut.String(), vaultconn.TextUnlinked) || out.Len() != 0 {
		t.Errorf("stdout %q stderr %q", out.String(), errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, state.StateFileName)); !os.IsNotExist(err) {
		t.Error("state file kept")
	}
}

func TestMCPNotPaired(t *testing.T) {
	var out, errOut bytes.Buffer
	if rc := run([]string{"mcp", "--state-dir", filepath.Join(t.TempDir(), "s")}, &out, &errOut); rc != 1 || !strings.Contains(errOut.String(), "not paired") || out.Len() != 0 {
		t.Errorf("exit %d stdout %q stderr %q", rc, out.String(), errOut.String())
	}
	if rc := run([]string{"mcp", "--state-dir", "x", "--access-minutes", "0"}, &out, &errOut); rc != 2 {
		t.Errorf("--access-minutes 0: exit %d", rc)
	}
	if rc := run([]string{"mcp"}, &out, &errOut); rc != 2 {
		t.Errorf("no --state-dir: exit %d", rc)
	}
}

const (
	toolItem     = "01JB2Z6V9K3M4N5P6Q7R8S9XYZ"
	referredItem = "01JB2Z6V9K3M4N5P6Q7R8S9XY0"
	toolValue    = "tool-test-value-not-a-secret"
)

// lineLog keeps everything written, for the stdout check, and passes it
// on.
type lineLog struct {
	mu  sync.Mutex
	w   io.Writer
	buf bytes.Buffer
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.buf.Write(p)
	l.mu.Unlock()
	return l.w.Write(p)
}

func (l *lineLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// fakeAgentVault answers agent.request like a vault (VAULT-MESSAGING
// §10.11): catalog, item.get and item.use at once, except item.get of
// referredItem, which is held for approval (approval.waiting) and
// answered when the test sends the answer. It returns the ids of held
// requests.
func fakeAgentVault(t *testing.T, v *pairtest.Vault) <-chan string {
	held := make(chan string, 4)
	itemBody := func(id string) []byte {
		return []byte(`{"item_id":"` + id + `","name":"Example","category":"login","fields":[{"field_id":"password","label":"Password","kind":"password","value":"` + toolValue + `"}]}`)
	}
	v.OnRequest = func(id, typ string, body []byte) {
		if typ != "agent.request" {
			return
		}
		var b struct {
			Op      string `json:"op"`
			ItemID  string `json:"item_id"`
			FieldID string `json:"field_id"`
		}
		_ = json.Unmarshal(body, &b)
		switch {
		case b.Op == "catalog":
			_, _ = v.SendResponse(id, typ, []byte(`{"items":[{"item_id":"`+toolItem+`","name":"Example","category":"login","labels":[{"field_id":"password","label":"Password","kind":"password"}]}]}`), "")
		case b.Op == "item.get" && b.ItemID == referredItem:
			exp := time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
			_, _ = v.SendEvent("approval.waiting", []byte(`{"approval_id":"01JB2Z6V9K3M4N5P6Q7R8S9APP","request_id":"`+id+`","exp":"`+exp+`"}`))
			held <- id
		case b.Op == "item.get":
			_, _ = v.SendResponse(id, typ, itemBody(b.ItemID), "")
		case b.Op == "item.use":
			mac := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
			_, _ = v.SendResponse(id, typ, []byte(`{"item_id":"`+b.ItemID+`","field_id":"`+b.FieldID+`","action":"hmac-sha256","result":"`+mac+`"}`), "")
		}
	}
	return held
}

func callTool(t *testing.T, cs *sdk.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var sc map[string]any
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return sc, res.IsError
}

// TestMCPTools: the MCP Go SDK's client starts a session with `mcp`
// over its standard input and output, lists the tools and calls every
// one against the fake vault connection (pairtest's relay and vault,
// with a real vaultconn, access manager, grants and requests behind the
// server): a catalog, an item read at once, an HMAC, an item held for
// approval that comes back pending and is then collected with
// leash.check_status, an unknown request id, and connection_info. It
// then closes standard input and `mcp` exits 0. Everything on standard
// output (and on the process's real standard output) is one JSON-RPC
// 2.0 message per line; nothing on standard error holds the value.
func TestMCPTools(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	held := fakeAgentVault(t, v)

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	withTestMCP(t, v, inR)
	mcpRequestOptions = func(o *request.Options) { o.Wait = 2 * time.Second }
	t.Cleanup(func() { mcpRequestOptions = nil })
	// Anything written to the process's standard output by any code
	// lands here (the test framework's own output goes elsewhere once
	// the test ends).
	realOut := os.Stdout
	strayR, strayW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = strayW
	strayDone := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(strayR); strayDone <- b }()
	defer func() { os.Stdout = realOut }()

	stdout := &lineLog{w: outW}
	var errOut syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"mcp", "--state-dir", dir, "--verbose"}, stdout, &errOut)
		outW.Close()
	}()

	client := sdk.NewClient(&sdk.Implementation{Name: "vettid-agent-test", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		t.Fatalf("connect: %v (stderr %s)", err, errOut.String())
	}
	lt, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range lt.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, " ") != "leash.list_available leash.request_secret leash.execute_action leash.check_status leash.connection_info" {
		t.Fatalf("tools: %v", names)
	}

	sc, isErr := callTool(t, cs, "leash.list_available", nil)
	if items, _ := sc["items"].([]any); isErr || len(items) != 1 {
		t.Fatalf("list_available: %v (stderr %s)", sc, errOut.String())
	}
	sc, isErr = callTool(t, cs, "leash.request_secret", map[string]any{"item_id": toolItem})
	if f, _ := sc["item"].(map[string]any)["fields"].([]any); isErr || len(f) != 1 || f[0].(map[string]any)["value"] != toolValue {
		t.Fatalf("request_secret: %v", sc)
	}
	sc, isErr = callTool(t, cs, "leash.execute_action", map[string]any{"item_id": toolItem, "field_id": "password", "data": "challenge"})
	if isErr || sc["result"] != base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("execute_action: %v", sc)
	}

	sc, isErr = callTool(t, cs, "leash.request_secret", map[string]any{"item_id": referredItem, "fields": []string{"password"}})
	if isErr || sc["status"] != "pending" || sc["waiting_for_approval"] != true {
		t.Fatalf("referred request_secret: %v", sc)
	}
	reqID, _ := sc["request_id"].(string)
	var heldID string
	select {
	case heldID = <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("not held")
	}
	if heldID != reqID {
		t.Fatalf("request id %q, vault held %q", reqID, heldID)
	}
	sc, isErr = callTool(t, cs, "leash.check_status", map[string]any{"request_id": reqID})
	if isErr || sc["status"] != "pending" {
		t.Fatalf("check_status before the approval: %v", sc)
	}
	if _, err := v.SendResponse(reqID, "agent.request", []byte(`{"item_id":"`+referredItem+`","name":"Example","category":"login","fields":[{"field_id":"password","label":"Password","kind":"password","value":"`+toolValue+`"}]}`), ""); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		sc, isErr = callTool(t, cs, "leash.check_status", map[string]any{"request_id": reqID})
		if sc["status"] != "pending" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("still pending after the approval")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if f, _ := sc["item"].(map[string]any)["fields"].([]any); isErr || len(f) != 1 || f[0].(map[string]any)["value"] != toolValue {
		t.Fatalf("check_status after the approval: %v", sc)
	}
	sc, isErr = callTool(t, cs, "leash.check_status", map[string]any{"request_id": reqID})
	if !isErr || sc["code"] != "expired" {
		t.Fatalf("check_status once returned: %v", sc)
	}

	sc, isErr = callTool(t, cs, "leash.connection_info", nil)
	if isErr || sc["device_id"] != pairtest.DeviceID || sc["access_session"] != "active" || sc["waiting_for_daily_check"] != false {
		t.Fatalf("connection_info: %v", sc)
	}

	if err := cs.Close(); err != nil {
		t.Logf("close: %v", err)
	}
	inW.Close()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("exit %d: %s", rc, errOut.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("mcp did not exit when standard input closed")
	}
	os.Stdout = realOut
	strayW.Close()
	if stray := <-strayDone; len(stray) != 0 {
		t.Errorf("written to the process's standard output: %q", stray)
	}

	out := stdout.String()
	if out == "" || !strings.HasSuffix(out, "\n") {
		t.Fatalf("standard output: %q", out)
	}
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(l), &m); err != nil || string(m["jsonrpc"]) != `"2.0"` {
			t.Errorf("not a JSON-RPC 2.0 message on standard output: %q", l)
		}
	}
	if strings.Contains(errOut.String(), toolValue) {
		t.Error("standard error holds the item's value")
	}
	if !strings.Contains(errOut.String(), "tool call") {
		t.Errorf("no tool call logged with --verbose: %s", errOut.String())
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestMCPSecondInstance: a second `mcp` on the same state directory
// exits 1 with "in use by another agent app" and writes nothing to
// standard output; the first keeps running.
func TestMCPSecondInstance(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	pr, pw := io.Pipe()
	withTestMCP(t, v, pr)
	done := make(chan int, 1)
	var errOut syncBuffer
	go func() { done <- run([]string{"mcp", "--state-dir", dir}, io.Discard, &errOut) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(strings.Join(v.Received(), ","), "vault.status") {
		if time.Now().After(deadline) {
			t.Fatal("no vault.status")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var out, errOut2 bytes.Buffer
	if rc := run([]string{"mcp", "--state-dir", dir}, &out, &errOut2); rc != 1 {
		t.Errorf("second mcp: exit %d", rc)
	}
	if !strings.Contains(errOut2.String(), "in use by another agent app") || out.Len() != 0 {
		t.Errorf("second mcp: stdout %q stderr %q", out.String(), errOut2.String())
	}
	select {
	case rc := <-done:
		t.Fatalf("the first mcp exited (%d): %s", rc, errOut.String())
	default:
	}
	pw.Close()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("first mcp: exit %d: %s", rc, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first mcp did not exit")
	}
}

// TestMCPHeldRecheck: while the vault is held (owner_check_required), a
// tool call has the connector ask vault.status again, at most once a
// minute, so that the hold ends promptly after the member's daily check.
func TestMCPHeldRecheck(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	v.GrantListError = "owner_check_required"
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	withTestMCP(t, v, inR)
	var errOut syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"mcp", "--state-dir", dir}, outW, &errOut)
		outW.Close()
	}()
	client := sdk.NewClient(&sdk.Implementation{Name: "vettid-agent-test", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: outR, Writer: inW}, nil)
	if err != nil {
		t.Fatal(err)
	}
	statuses := func() int { return strings.Count(strings.Join(v.Received(), ","), "vault.status") }
	deadline := time.Now().Add(10 * time.Second)
	for statuses() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("no vault.status at start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	sc, isErr := callTool(t, cs, "leash.list_available", nil)
	if !isErr || sc["code"] != "owner_check_required" {
		t.Fatalf("first call: %v", sc)
	}
	sc, _ = callTool(t, cs, "leash.connection_info", nil)
	if sc["waiting_for_daily_check"] != true {
		t.Errorf("connection_info while held: %v", sc)
	}
	deadline = time.Now().Add(10 * time.Second)
	for statuses() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("no vault.status after a tool call while held")
		}
		time.Sleep(10 * time.Millisecond)
	}
	callTool(t, cs, "leash.list_available", nil)
	callTool(t, cs, "leash.connection_info", nil)
	time.Sleep(200 * time.Millisecond)
	if n := statuses(); n != 2 {
		t.Errorf("%d vault.status, want 2 (at most one a minute)", n)
	}
	_ = cs.Close()
	inW.Close()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("mcp did not exit")
	}
}

// stopWithUnreadStdout runs `mcp` with standard output w, which nobody
// reads, sends enough pings to block a write to it, then sends the
// signal: `mcp` must exit within a bounded time. It returns standard
// error.
func stopWithUnreadStdout(t *testing.T, w io.Writer) string {
	t.Helper()
	v := newVault(t)
	dir := pairedDir(t, v)
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	withTestMCP(t, v, pr)
	sigCtx, sendSignal := context.WithCancel(context.Background())
	oldSignals, oldWait := mcpSignals, mcpStopWait
	mcpSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return context.WithCancel(sigCtx)
	}
	mcpStopWait = 100 * time.Millisecond
	t.Cleanup(func() { mcpSignals, mcpStopWait = oldSignals, oldWait })
	errOut := &lineLog{w: io.Discard}
	done := make(chan int, 1)
	go func() { done <- run([]string{"mcp", "--state-dir", dir}, w, errOut) }()
	// More answers than a pipe buffers (64 KiB on Linux and macOS):
	// sent from a goroutine, as the input stops being read once a write
	// blocks.
	go func() {
		ping := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}` + "\n")
		for i := 0; i < 4000; i++ {
			if _, err := pw.Write(ping); err != nil {
				return
			}
		}
	}()
	time.Sleep(300 * time.Millisecond) // the writes block
	start := time.Now()
	sendSignal()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("exit %d", rc)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mcp did not exit after the signal")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("exit took %v", d)
	} else if d < mcpStopWait {
		t.Errorf("exit after %v: no write was blocked, which the test needs", d)
	}
	errOut.mu.Lock()
	defer errOut.mu.Unlock()
	return errOut.buf.String()
}

const textUnreadStdout = "does not read standard output"

// TestMCPSignalUnreadStdout: a signal stops `mcp` within a bounded time
// although a write to standard output is blocked (the MCP client keeps
// it open and does not read it), where standard output has no write
// deadline (here an in-process pipe): the write is abandoned and said
// so on standard error.
func TestMCPSignalUnreadStdout(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close() // ends the abandoned write
	if errOut := stopWithUnreadStdout(t, pw); !strings.Contains(errOut, textUnreadStdout) {
		t.Errorf("stderr: %q", errOut)
	}
}

// TestMCPSignalUnreadStdoutFile: the same with an OS pipe. Where the Go
// runtime polls it (Linux, macOS), the write deadline ends the blocked
// write and the session ends normally; elsewhere the write is
// abandoned.
func TestMCPSignalUnreadStdoutFile(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	errOut := stopWithUnreadStdout(t, w)
	if runtime.GOOS != "windows" && strings.Contains(errOut, textUnreadStdout) {
		t.Errorf("the write deadline did not end the write: %q", errOut)
	}
}
