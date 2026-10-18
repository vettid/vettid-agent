// Package mcp is the connector's MCP server (AGENT-PLAN §2 AG1, AG1a,
// AG5, AG9, §4.1, §6 A3.3): the five LEASH tools over the stdio
// transport, behind the local rate limit.
//
// The transport is MCP's stdio transport: JSON-RPC 2.0 messages, one per
// line, read from standard input and written to standard output. The
// server speaks the MCP versions in ProtocolVersions (the lifecycle with
// `initialize`); it offers tools only, sends no requests of its own and
// no notifications, and refuses JSON-RPC batches. Nothing but MCP
// messages is ever written to its output; diagnostics go to the logger
// (standard error), with tool names, codes and request ids only.
//
// A tool call runs in a goroutine of its own (at most MaxInFlight at
// once; the read loop answers a call beyond that, or over the rate
// limit, itself, and so blocks while the client does not read) and is
// answered when it ends (AG9: within about 20 s, with a pending answer if the vault has
// not answered by then). notifications/cancelled cancels a call, which
// is then not answered. When the input ends, the calls in progress are
// cancelled and Serve returns once they have ended.
//
// The package sees results, never keys (AGENT-PLAN §3.1). A result that
// holds item values is written from one byte slice that is zeroed once
// written, and the request's Result is wiped (encode.go).
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/vettid/vettid-agent/internal/leash"
	"github.com/vettid/vettid-agent/internal/leash/request"
)

// ProtocolVersions are the MCP versions this server speaks, newest
// first. A client asking for another gets the newest (MCP lifecycle,
// version negotiation).
var ProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// DefaultMaxLine bounds one incoming message (the largest valid tool
// call, leash.execute_action with 16,384 bytes of data in base64, is far
// smaller).
const DefaultMaxLine = 1 << 20

// JSON-RPC error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

// Requests is what the tools use of *request.Client.
type Requests interface {
	Catalog(ctx context.Context) (*request.Outcome, error)
	Get(ctx context.Context, itemID string, fields []string) (*request.Outcome, error)
	Use(ctx context.Context, itemID, fieldID string, data []byte) (*request.Outcome, error)
	Status(ctx context.Context, requestID string) (*request.Outcome, error)
}

// Options configure New.
type Options struct {
	Requests Requests
	// Info returns what leash.connection_info shows (internal/leash).
	Info func() leash.Info
	// Held reports whether the vault waits for the member's daily check
	// (nil: never).
	Held func() bool
	// BeforeCall, if set, runs at the start of every tool call that
	// passed the rate limit (cmd/vettid-agent: a vault.status while the
	// vault is held, internal/access CheckHold). It must not block.
	BeforeCall func()
	// Version is the connector's version for serverInfo.
	Version string
	// Log is for diagnostics; nil discards.
	Log *slog.Logger
	// Now, Rate, Burst and MaxLine default to time.Now, DefaultRate,
	// DefaultBurst and DefaultMaxLine.
	Now     func() time.Time
	Rate    float64
	Burst   int
	MaxLine int
}

// Server is one MCP session over one input and output.
type Server struct {
	o     Options
	log   *slog.Logger
	limit *bucket
	tools map[string]*tool
	list  []byte // the tools/list result

	wmu     sync.Mutex
	out     io.Writer
	stopped bool

	mu          sync.Mutex
	initialized bool
	calls       map[string]context.CancelFunc
	wg          sync.WaitGroup
	// slots bounds the tool calls in flight (MaxInFlight); a call that
	// finds none is answered from the read loop.
	slots chan struct{}
}

// MaxInFlight bounds the tool calls running at once (chosen; not in the
// spec). Every other answer, including the refusal of a call beyond
// this bound or over the rate limit, is written by the read loop
// itself, so that a client that stops reading standard output stops
// the server reading standard input: goroutines and memory stay
// bounded.
const MaxInFlight = 64

// New returns a Server.
func New(o Options) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rate <= 0 {
		o.Rate = DefaultRate
	}
	if o.Burst <= 0 {
		o.Burst = DefaultBurst
	}
	if o.MaxLine <= 0 {
		o.MaxLine = DefaultMaxLine
	}
	if o.Held == nil {
		o.Held = func() bool { return false }
	}
	s := &Server{o: o, log: o.Log, limit: newBucket(o.Rate, o.Burst, o.Now), calls: map[string]context.CancelFunc{},
		slots: make(chan struct{}, MaxInFlight)}
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s.tools = map[string]*tool{}
	var defs []toolDef
	for _, t := range s.toolSet() {
		s.tools[t.def.Name] = t
		defs = append(defs, t.def)
	}
	s.list, _ = json.Marshal(map[string]any{"tools": defs})
	return s
}

// line is one message read from the input, or a line that was too long.
type line struct {
	b       []byte
	tooLong bool
}

// Serve reads messages from in and writes the answers to out until in
// ends (it then returns nil) or ctx ends (ctx.Err()). The calls in
// progress are cancelled and waited for before it returns; nothing is
// written to out after it returns. The goroutine reading in may stay
// blocked in a Read after a return caused by ctx.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	s.wmu.Lock()
	s.out = out
	s.wmu.Unlock()
	defer func() {
		cancel()
		s.wg.Wait()
		s.wmu.Lock()
		s.stopped = true
		s.wmu.Unlock()
	}()
	lines := make(chan line)
	readErr := make(chan error, 1)
	go s.read(ctx, in, lines, readErr)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case l := <-lines:
			if l.tooLong {
				s.log.Warn("MCP message refused", "code", codeInvalidRequest, "reason", "too long")
				s.writeError(nil, codeInvalidRequest, "message too long")
				continue
			}
			s.handle(ctx, l.b)
		}
	}
}

// read sends each line of in to lines, then the error that ended it.
func (s *Server) read(ctx context.Context, in io.Reader, lines chan<- line, errc chan<- error) {
	r := bufio.NewReaderSize(in, s.o.MaxLine)
	send := func(l line) bool {
		select {
		case lines <- l:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for {
		b, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// Skip to the end of the line.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			if !send(line{tooLong: true}) {
				return
			}
			if err != nil {
				errc <- err
				return
			}
			continue
		}
		if len(bytes.TrimSpace(b)) > 0 && !send(line{b: bytes.Clone(b)}) {
			return
		}
		if err != nil {
			errc <- err
			return
		}
	}
}

// message is a JSON-RPC 2.0 message as received.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// MaxIDLength bounds a request id as received (chosen; not in the
// spec): ids are kept while a call runs and repeated in its answer.
const MaxIDLength = 256

// validID reports whether raw is a JSON-RPC id MCP allows: a string or
// a number (not null), at most MaxIDLength bytes.
func validID(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > MaxIDLength {
		return false
	}
	switch raw[0] {
	case '"':
		var s string
		return json.Unmarshal(raw, &s) == nil
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		var n json.Number
		return json.Unmarshal(raw, &n) == nil
	}
	return false
}

func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// handle answers one message.
func (s *Server) handle(ctx context.Context, b []byte) {
	b = bytes.TrimSpace(b)
	if b[0] == '[' {
		s.log.Warn("MCP message refused", "code", codeInvalidRequest, "reason", "batch")
		s.writeError(nil, codeInvalidRequest, "batches are not supported")
		return
	}
	var m message
	if err := json.Unmarshal(b, &m); err != nil {
		s.log.Warn("MCP message refused", "code", codeParse)
		s.writeError(nil, codeParse, "parse error")
		return
	}
	hasID := !isNull(m.ID)
	var id json.RawMessage
	if hasID {
		if !validID(m.ID) {
			s.log.Warn("MCP message refused", "code", codeInvalidRequest, "reason", "id")
			s.writeError(nil, codeInvalidRequest, "the id must be a string or a number of at most 256 bytes")
			return
		}
		id = appendCompact(nil, m.ID)
	}
	if m.JSONRPC != "2.0" {
		s.log.Warn("MCP message refused", "code", codeInvalidRequest, "reason", "version")
		s.writeError(id, codeInvalidRequest, `jsonrpc must be "2.0"`)
		return
	}
	switch {
	case m.Method != "" && hasID:
		s.request(ctx, id, m.Method, m.Params)
	case m.Method != "":
		s.notification(m.Method, m.Params)
	case hasID && (m.Result != nil || m.Error != nil):
		// A response: this server sends no requests, so there is
		// nothing to match it with.
	default:
		s.log.Warn("MCP message refused", "code", codeInvalidRequest)
		s.writeError(id, codeInvalidRequest, "invalid request")
	}
}

func (s *Server) isInitialized() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initialized
}

// request answers a request.
func (s *Server) request(ctx context.Context, id json.RawMessage, method string, params json.RawMessage) {
	switch method {
	case "initialize":
		s.initialize(id, params)
		return
	case "ping":
		s.writeResult(id, struct{}{})
		return
	}
	if !s.isInitialized() {
		s.writeError(id, codeInvalidRequest, "the session is not initialized: send initialize first")
		return
	}
	switch method {
	case "tools/list":
		s.writeRaw(id, s.list)
	case "tools/call":
		s.call(ctx, id, params)
	default:
		s.writeError(id, codeMethodNotFound, "method not found")
	}
}

// notification takes a notification.
func (s *Server) notification(method string, params json.RawMessage) {
	switch method {
	case "notifications/initialized":
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(params, &p) != nil || !validID(p.RequestID) {
			return
		}
		key := string(appendCompact(nil, p.RequestID))
		s.mu.Lock()
		cancel := s.calls[key]
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}

// Instructions is the initialize result's text for the agent.
const Instructions = "These tools reach the member's VettID vault, within the grants and approvals the member gives on their phone. " +
	"Values come from the member's vault and are the member's secrets. Prefer leash.execute_action to leash.request_secret: " +
	"with it the value never leaves the vault. A tool that answers {\"status\":\"pending\"} waits for the member: " +
	"check again later with leash.check_status. Errors carry a stable code."

func (s *Server) initialize(id, params json.RawMessage) {
	var p struct {
		ProtocolVersion *string `json:"protocolVersion"`
	}
	if json.Unmarshal(params, &p) != nil || p.ProtocolVersion == nil {
		s.writeError(id, codeInvalidParams, "initialize needs protocolVersion")
		return
	}
	s.mu.Lock()
	again := s.initialized
	s.initialized = true
	s.mu.Unlock()
	if again {
		s.writeError(id, codeInvalidRequest, "the session is already initialized")
		return
	}
	v := ProtocolVersions[0]
	if slices.Contains(ProtocolVersions, *p.ProtocolVersion) {
		v = *p.ProtocolVersion
	}
	s.log.Info("MCP session initialized", "protocol", v)
	s.writeResult(id, map[string]any{
		"protocolVersion": v,
		"capabilities":    map[string]any{"tools": map[string]bool{"listChanged": false}},
		"serverInfo":      map[string]string{"name": "vettid-agent", "title": "VettID agent connector", "version": s.o.Version},
		"instructions":    Instructions,
	})
}

// call starts a tool call in a goroutine of its own.
func (s *Server) call(ctx context.Context, id, params json.RawMessage) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(params, &p) != nil || p.Name == "" {
		s.writeError(id, codeInvalidParams, "tools/call needs a tool name")
		return
	}
	t := s.tools[p.Name]
	if t == nil {
		s.writeError(id, codeInvalidParams, "unknown tool")
		return
	}
	args := bytes.TrimSpace(p.Arguments)
	if isNull(args) {
		args = []byte("{}")
	}
	if args[0] != '{' {
		s.writeError(id, codeInvalidParams, "the arguments must be an object")
		return
	}
	key := string(id)
	s.mu.Lock()
	_, dup := s.calls[key]
	s.mu.Unlock()
	if dup {
		s.writeError(id, codeInvalidRequest, "a request with this id is in progress")
		return
	}
	// The rate limit and the bound on calls in flight are applied here,
	// in the read loop, which writes their refusals itself (it blocks
	// while the client does not read).
	if ok, wait := s.limit.take(); !ok {
		out := rateLimited(s.o.Now(), wait)
		s.log.Info("tool call", "tool", t.def.Name, "outcome", out.logCode)
		s.writeToolResult(id, out)
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		out := tooManyInFlight()
		s.log.Info("tool call", "tool", t.def.Name, "outcome", out.logCode)
		s.writeToolResult(id, out)
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.calls[key] = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.calls, key)
			s.mu.Unlock()
			cancel()
			<-s.slots
		}()
		out := s.runTool(cctx, t, args)
		defer out.wipe()
		if cctx.Err() != nil {
			// Cancelled by the client, or the session ended: no answer.
			s.log.Info("tool call cancelled", "tool", t.def.Name)
			return
		}
		s.log.Info("tool call", "tool", t.def.Name, "outcome", out.logCode, "request_id", out.requestID)
		s.writeToolResult(id, out)
	}()
}

// runTool runs the tool (the rate limit was applied by call).
func (s *Server) runTool(ctx context.Context, t *tool, args json.RawMessage) *toolOut {
	if s.o.BeforeCall != nil {
		s.o.BeforeCall()
	}
	return t.run(ctx, args)
}

// write writes one message (b, newline-terminated) unless Serve has
// returned.
func (s *Server) write(b []byte) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.stopped || s.out == nil {
		return
	}
	if _, err := s.out.Write(b); err != nil {
		s.log.Warn("MCP message not written", "err", "write failed")
	}
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) writeError(id json.RawMessage, code int, msg string) {
	if id == nil {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   rpcError        `json:"error"`
	}{"2.0", id, rpcError{code, msg}})
	s.write(append(b, '\n'))
}

func (s *Server) writeResult(id json.RawMessage, v any) {
	r, err := json.Marshal(v)
	if err != nil {
		s.writeError(id, -32603, "internal error")
		return
	}
	s.writeRaw(id, r)
}

func (s *Server) writeRaw(id, result json.RawMessage) {
	b, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{"2.0", id, result})
	s.write(append(b, '\n'))
}

// The fixed parts of a tool result message (writeToolResult).
const (
	trHead = `{"jsonrpc":"2.0","id":`
	trMid1 = `,"result":{"content":[{"type":"text","text":`
	trMid2 = `}],"structuredContent":`
	trMid3 = `,"isError":`
	trTail = "}}\n"
)

// toolResultSize is the most bytes writeToolResult's message takes.
func toolResultSize(id, body []byte) int {
	return len(trHead) + len(id) + len(trMid1) + quotedBound(len(body)) + len(trMid2) + len(body) + len(trMid3) + len("false") + len(trTail)
}

// writeToolResult writes a tool's result: its structured content, and
// the same JSON as the text content (MCP: a tool that returns
// structured content should also return it serialised as text, for
// clients that pass only the text to the model). The message is built
// in one byte slice, sized up front, and zeroed once written.
func (s *Server) writeToolResult(id json.RawMessage, out *toolOut) {
	b := make([]byte, 0, toolResultSize(id, out.body))
	b = append(b, trHead...)
	b = append(b, id...)
	b = append(b, trMid1...)
	b = appendQuoted(b, out.body)
	b = append(b, trMid2...)
	b = append(b, out.body...)
	b = append(b, trMid3...)
	if out.isError {
		b = append(b, "true"...)
	} else {
		b = append(b, "false"...)
	}
	b = append(b, trTail...)
	s.write(b)
	clear(b)
}
