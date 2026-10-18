package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/leash"
	"github.com/vettid/vettid-agent/internal/leash/request"
)

const (
	testItem    = "01JB2Z6V9K3M4N5P6Q7R8S9XYZ"
	testRequest = "01JB2Z6V9K3M4N5P6Q7R8S9REQ"
	testSecret  = "test-value-not-a-secret"
)

// call is one call the fake saw.
type call struct {
	op      string
	itemID  string
	fieldID string
	fields  []string
	data    []byte
	reqID   string
}

// fakeRequests answers from functions; the default answers are fixed
// fake values.
type fakeRequests struct {
	mu    sync.Mutex
	calls []call
	// results handed out, to check they were wiped
	results []*request.Result

	catalog func() (*request.Outcome, error)
	get     func(itemID string, fields []string) (*request.Outcome, error)
	use     func(itemID, fieldID string, data []byte) (*request.Outcome, error)
	status  func(id string) (*request.Outcome, error)
	block   chan struct{} // if set, every call waits on it or its ctx
}

func (f *fakeRequests) record(ctx context.Context, c call) error {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	block := f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (f *fakeRequests) keep(o *request.Outcome, err error) (*request.Outcome, error) {
	if o != nil && o.Result != nil {
		f.mu.Lock()
		f.results = append(f.results, o.Result)
		f.mu.Unlock()
	}
	return o, err
}

func (f *fakeRequests) Catalog(ctx context.Context) (*request.Outcome, error) {
	if err := f.record(ctx, call{op: "catalog"}); err != nil {
		return nil, err
	}
	if f.catalog != nil {
		return f.keep(f.catalog())
	}
	return f.keep(&request.Outcome{Result: &request.Result{Op: request.OpCatalog, Catalog: []request.CatalogItem{
		{ItemID: testItem, Name: "Example login", Category: "login", Labels: []request.Label{
			{FieldID: "username", Label: "Username", Kind: "text"}, {FieldID: "password", Label: "Password", Kind: "password"}}},
		{ItemID: "01JB2Z6V9K3M4N5P6Q7R8S9AAA", Name: "Empty note", Category: "note"},
	}}}, nil)
}

func fakeItem() *request.Result {
	return &request.Result{Op: request.OpGet, Item: &request.Item{ItemID: testItem, Name: "Example login", Category: "login",
		Fields: []request.Field{
			{FieldID: "username", Label: "Username", Kind: "text", Value: json.RawMessage(`"member@example.test"`)},
			{FieldID: "password", Label: "Password", Kind: "password", Value: json.RawMessage(`"` + testSecret + `"`)},
			{FieldID: "address", Label: "Address", Kind: "address", Value: json.RawMessage("{\n  \"city\": \"Testville\",\n  \"line1\": \"1 \\\"Quoted\\\" St\"\n}")},
			{FieldID: "empty", Label: "Empty", Kind: "text"},
		},
		Notes: json.RawMessage("\"note line 1\\nline 2 \u2028 <&> \xff\"")}}
}

func (f *fakeRequests) Get(ctx context.Context, itemID string, fields []string) (*request.Outcome, error) {
	if err := f.record(ctx, call{op: "get", itemID: itemID, fields: fields}); err != nil {
		return nil, err
	}
	if f.get != nil {
		return f.keep(f.get(itemID, fields))
	}
	return f.keep(&request.Outcome{Result: fakeItem()}, nil)
}

func (f *fakeRequests) Use(ctx context.Context, itemID, fieldID string, data []byte) (*request.Outcome, error) {
	if err := f.record(ctx, call{op: "use", itemID: itemID, fieldID: fieldID, data: bytes.Clone(data)}); err != nil {
		return nil, err
	}
	if f.use != nil {
		return f.keep(f.use(itemID, fieldID, data))
	}
	mac := make([]byte, 32)
	for i := range mac {
		mac[i] = byte(i)
	}
	return f.keep(&request.Outcome{Result: &request.Result{Op: request.OpUse,
		Use: &request.Use{ItemID: itemID, FieldID: fieldID, Action: "hmac-sha256", Result: mac}}}, nil)
}

func (f *fakeRequests) Status(ctx context.Context, id string) (*request.Outcome, error) {
	if err := f.record(ctx, call{op: "status", reqID: id}); err != nil {
		return nil, err
	}
	if f.status != nil {
		return f.keep(f.status(id))
	}
	return nil, request.ErrExpired
}

func (f *fakeRequests) seen() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func fakeInfo() leash.Info {
	t := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	until := t.Add(time.Hour)
	exp := t.Add(30 * 24 * time.Hour)
	return leash.Info{VaultID: "vault-test", DeviceID: "device-test", Name: "Agent on test", LastContact: &t,
		AccessSession: "active", AccessSessionUntil: &until, GrantsAsOf: &t, GrantsConfirmed: true,
		Grants: []leash.GrantInfo{{GrantID: "01JB2Z6V9K3M4N5P6Q7R8S9GRA", Scope: "items.read", Approval: "ask",
			PerHour: 60, PerDay: 600, ExpiresAt: &exp, StatusUntil: &until}}}
}

// clock is a settable time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// session is a Server over pipes, driven with raw JSON-RPC lines.
type session struct {
	t      *testing.T
	f      *fakeRequests
	srv    *Server
	in     *io.PipeWriter
	out    *bufio.Reader
	outW   *io.PipeWriter
	done   chan error
	cancel context.CancelFunc
	clock  *clock
	writes *writeLog
}

// writeLog keeps every slice the server wrote, as passed (not copied),
// and a copy of it.
type writeLog struct {
	mu     sync.Mutex
	w      io.Writer
	passed [][]byte
	copies [][]byte
}

func (l *writeLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.passed = append(l.passed, p)
	l.copies = append(l.copies, bytes.Clone(p))
	l.mu.Unlock()
	return l.w.Write(p)
}

func newSession(t *testing.T, f *fakeRequests, mod func(*Options)) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &clock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	o := Options{Requests: f, Info: fakeInfo, Version: "test", Now: c.Now}
	if mod != nil {
		mod(&o)
	}
	s := &session{t: t, f: f, srv: New(o), in: inW, out: bufio.NewReader(outR), outW: outW, done: make(chan error, 1), clock: c,
		writes: &writeLog{w: outW}}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() { s.done <- s.srv.Serve(ctx, inR, s.writes); outW.Close() }()
	t.Cleanup(func() {
		inW.Close()
		cancel()
		<-s.done
	})
	return s
}

func (s *session) send(line string) {
	s.t.Helper()
	if _, err := io.WriteString(s.in, line+"\n"); err != nil {
		s.t.Fatal(err)
	}
}

// recv reads one message within 5 s.
func (s *session) recv() map[string]any {
	s.t.Helper()
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		b, err := s.out.ReadBytes('\n')
		ch <- res{b, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			s.t.Fatalf("read: %v", r.err)
		}
		var m map[string]any
		if err := json.Unmarshal(r.b, &m); err != nil {
			s.t.Fatalf("not JSON: %q", r.b)
		}
		return m
	case <-time.After(5 * time.Second):
		s.t.Fatal("no answer")
	}
	return nil
}

func (s *session) init() {
	s.t.Helper()
	s.send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	s.recv()
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

// toolCall sends tools/call and returns the result's structured content
// and isError.
func (s *session) toolCall(id int, name, args string) (map[string]any, bool) {
	s.t.Helper()
	s.send(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`)
	m := s.recv()
	r, ok := m["result"].(map[string]any)
	if !ok {
		s.t.Fatalf("no result: %v", m)
	}
	sc, _ := r["structuredContent"].(map[string]any)
	isErr, _ := r["isError"].(bool)
	return sc, isErr
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// recvRaw reads one message within 5 s, as written.
func (s *session) recvRaw() []byte {
	s.t.Helper()
	ch := make(chan []byte, 1)
	go func() {
		b, _ := s.out.ReadBytes('\n')
		ch <- b
	}()
	select {
	case b := <-ch:
		return b
	case <-time.After(5 * time.Second):
		s.t.Fatal("no answer")
	}
	return nil
}
