package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-agent/internal/leash/request"
)

// TestSecretWiped: after leash.request_secret's and
// leash.execute_action's results are written, the slice the server
// wrote and the request's Result are zeroed.
func TestSecretWiped(t *testing.T) {
	f := &fakeRequests{}
	s := newSession(t, f, nil)
	s.init()
	sc, isErr := s.toolCall(1, ToolRequestSecret, `{"item_id":"`+testItem+`"}`)
	if isErr || sc["status"] != "ok" {
		t.Fatalf("result: %v", sc)
	}
	sc, isErr = s.toolCall(2, ToolExecuteAction, `{"item_id":"`+testItem+`","field_id":"password","data":"x"}`)
	if isErr || sc["result"] != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" {
		t.Fatalf("result: %v", sc)
	}
	s.send(`{"jsonrpc":"2.0","id":3,"method":"ping"}`)
	s.recv() // the tool calls' goroutines have wiped by now: ping is answered after
	s.writes.mu.Lock()
	defer s.writes.mu.Unlock()
	found := 0
	for i, c := range s.writes.copies {
		if !bytes.Contains(c, []byte(testSecret)) && !bytes.Contains(c, []byte(`"result":"AAEC`)) {
			continue
		}
		found++
		if len(bytes.Trim(s.writes.passed[i], "\x00")) != 0 {
			t.Errorf("message %d was not zeroed after it was written", i)
		}
	}
	if found != 2 {
		t.Fatalf("%d secret messages written", found)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.results {
		if r.Item != nil {
			for _, fl := range r.Item.Fields {
				if len(bytes.Trim(fl.Value, "\x00")) != 0 {
					t.Errorf("field %s not wiped", fl.FieldID)
				}
			}
			if len(bytes.Trim(r.Item.Notes, "\x00")) != 0 {
				t.Error("notes not wiped")
			}
		}
		if r.Use != nil && len(bytes.Trim(r.Use.Result, "\x00")) != 0 {
			t.Error("HMAC not wiped")
		}
	}
}

// TestRateLimit: 120 calls pass at once, the next is answered
// rate_limited_local without reaching the vault, and one more passes
// half a second later (2 a second).
func TestRateLimit(t *testing.T) {
	f := &fakeRequests{}
	var before atomic.Int32
	s := newSession(t, f, func(o *Options) { o.BeforeCall = func() { before.Add(1) } })
	s.init()
	for i := 0; i < DefaultBurst; i++ {
		if _, isErr := s.toolCall(i+1, ToolConnectionInfo, `{}`); isErr {
			t.Fatalf("call %d refused", i+1)
		}
	}
	sc, isErr := s.toolCall(1000, ToolListAvailable, `{}`)
	if !isErr || sc["code"] != "rate_limited_local" || sc["retry_after"] == nil {
		t.Fatalf("over the limit: %v", sc)
	}
	if len(f.seen()) != 0 {
		t.Error("a limited call reached the vault")
	}
	if before.Load() != DefaultBurst {
		t.Errorf("BeforeCall ran %d times", before.Load())
	}
	s.clock.Add(500 * time.Millisecond)
	if sc, isErr := s.toolCall(1001, ToolListAvailable, `{}`); isErr {
		t.Fatalf("after 0.5 s: %v", sc)
	}
	if _, isErr := s.toolCall(1002, ToolListAvailable, `{}`); !isErr {
		t.Fatal("a second call passed within 0.5 s")
	}
}

// TestCancelled: notifications/cancelled cancels the call, which is
// not answered.
func TestCancelled(t *testing.T) {
	f := &fakeRequests{block: make(chan struct{})}
	s := newSession(t, f, nil)
	s.init()
	s.send(`{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"leash.request_secret","arguments":{"item_id":"` + testItem + `"}}}`)
	deadline := time.Now().Add(5 * time.Second)
	for len(f.seen()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("call not started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A second call with the same id while the first runs is refused.
	s.send(`{"jsonrpc":"2.0","id":"c1","method":"tools/call","params":{"name":"leash.list_available","arguments":{}}}`)
	if m := s.recv(); m["error"] == nil {
		t.Fatalf("duplicate id: %v", m)
	}
	s.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"c1","reason":"test"}}`)
	time.Sleep(50 * time.Millisecond)
	s.send(`{"jsonrpc":"2.0","id":"p","method":"ping"}`)
	if m := s.recv(); m["id"] != "p" {
		t.Fatalf("the cancelled call was answered: %v", m)
	}
}

// TestEOF: when the input ends, calls in progress are cancelled, Serve
// returns nil, and nothing more is written.
func TestEOF(t *testing.T) {
	f := &fakeRequests{block: make(chan struct{})}
	s := newSession(t, f, nil)
	s.init()
	s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"leash.list_available","arguments":{}}}`)
	deadline := time.Now().Add(5 * time.Second)
	for len(f.seen()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("call not started")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.in.Close()
	select {
	case err := <-s.done:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
		s.done <- nil // for the cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return at EOF")
	}
	if b, err := s.out.ReadBytes('\n'); len(b) != 0 || err == nil {
		t.Errorf("written after EOF: %q", b)
	}
}

// TestProtocol: lines too long, notifications, responses and invalid
// messages; every answer is one line of JSON-RPC 2.0.
func TestProtocol(t *testing.T) {
	f := &fakeRequests{}
	s := newSession(t, f, func(o *Options) { o.MaxLine = 256 })
	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if m := s.recv(); m["error"].(map[string]any)["code"] != float64(codeInvalidParams) {
		t.Errorf("initialize without a version: %v", m)
	}
	s.init()
	s.send(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if m := s.recv(); m["error"] == nil {
		t.Errorf("second initialize: %v", m)
	}
	s.send(`{"jsonrpc":"2.0","id":3,"method":"ping","params":{"pad":"` + strings.Repeat("x", 400) + `"}}`)
	if m := s.recv(); m["error"].(map[string]any)["message"] != "message too long" {
		t.Errorf("long line: %v", m)
	}
	s.send(`{"jsonrpc":"2.0","method":"notifications/unknown"}`)
	s.send(`{"jsonrpc":"2.0","id":9,"result":{}}`)
	s.send(`{"jsonrpc":"1.0","id":4,"method":"ping"}`)
	if m := s.recv(); m["id"] != float64(4) || m["error"] == nil {
		t.Errorf("jsonrpc 1.0: %v", m)
	}
	s.send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"leash.list_available","arguments":[1]}}`)
	if m := s.recv(); m["error"].(map[string]any)["code"] != float64(codeInvalidParams) {
		t.Errorf("arguments not an object: %v", m)
	}
	s.send(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"leash.list_available"}}`)
	if m := s.recv(); m["result"] == nil {
		t.Errorf("no arguments: %v", m)
	}
	s.send(`{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if m := s.recv(); m["id"] != float64(7) {
		t.Errorf("after the rest: %v", m)
	}
}

// TestArguments: what each tool passes on, and arguments that do not
// match the schema.
func TestArguments(t *testing.T) {
	f := &fakeRequests{}
	s := newSession(t, f, nil)
	s.init()
	s.toolCall(1, ToolRequestSecret, `{"item_id":"`+testItem+`","fields":["password","username"]}`)
	s.toolCall(2, ToolRequestSecret, `{"item_id":"`+testItem+`","fields":null}`)
	s.toolCall(3, ToolExecuteAction, `{"item_id":"`+testItem+`","field_id":"password","data":"aGk=","data_encoding":"base64"}`)
	s.toolCall(4, ToolExecuteAction, `{"item_id":"`+testItem+`","field_id":"password","data":"aGk=","data_encoding":"text"}`)
	s.toolCall(5, ToolCheckStatus, `{"request_id":"`+testRequest+`"}`)
	got := f.seen()
	if len(got) != 5 ||
		strings.Join(got[0].fields, ",") != "password,username" || got[1].fields != nil ||
		string(got[2].data) != "hi" || string(got[3].data) != "aGk=" || got[2].fieldID != "password" ||
		got[4].reqID != testRequest {
		t.Fatalf("passed on: %+v", got)
	}
	for i, args := range []struct{ tool, args string }{
		{ToolRequestSecret, `{}`},
		{ToolRequestSecret, `{"item_id":"` + testItem + `","extra":1}`},
		{ToolRequestSecret, `{"item_id":5}`},
		{ToolExecuteAction, `{"item_id":"` + testItem + `","field_id":"password"}`},
		{ToolExecuteAction, `{"item_id":"` + testItem + `","field_id":"password","data":"x","data_encoding":"hex"}`},
		{ToolCheckStatus, `{}`},
		{ToolListAvailable, `{"x":1}`},
		{ToolConnectionInfo, `{"x":1}`},
	} {
		sc, isErr := s.toolCall(10+i, args.tool, args.args)
		if !isErr || sc["code"] != "bad_request" {
			t.Errorf("%s %s: %v", args.tool, args.args, sc)
		}
	}
	if len(f.seen()) != 5 {
		t.Error("invalid arguments reached the vault")
	}
}

// TestUnknownErrors: an error the tools do not know is answered without
// its text.
func TestUnknownErrors(t *testing.T) {
	f := &fakeRequests{catalog: func() (*request.Outcome, error) { return nil, errors.New("inner detail " + testSecret) }}
	s := newSession(t, f, nil)
	s.init()
	sc, isErr := s.toolCall(1, ToolListAvailable, `{}`)
	if !isErr || sc["code"] != "internal_error" || strings.Contains(sc["message"].(string), testSecret) {
		t.Fatalf("got %v", sc)
	}
}

// TestEncode: appendQuoted and appendCompact give valid JSON on one
// line that reads back as the input (invalid UTF-8 as U+FFFD).
func TestEncode(t *testing.T) {
	for _, in := range []string{"", "plain", "quote \" backslash \\ slash /", "ctl \x00\x01\x1f\x7f \n\r\t", "\u00e9 \u00fc \u6f22 \U0001f642",
		"sep \u2028 \u2029", "bad \xff \xc3 end", "<&>"} {
		q := appendQuoted(nil, []byte(in))
		if !utf8.Valid(q) || bytes.ContainsAny(q, "\n\r") || len(q) > quotedBound(len(in)) {
			t.Errorf("%q: %q", in, q)
		}
		var back string
		if err := json.Unmarshal(q, &back); err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if want := strings.ToValidUTF8(in, "\ufffd"); utf8.ValidString(in) && back != in || !utf8.ValidString(in) && !strings.HasPrefix(back, want[:3]) {
			t.Errorf("%q read back as %q", in, back)
		}
	}
	raw := []byte("{\n  \"a\" : [ 1 , 2 ],\n\t\"b\": \"x y\\n\\\" \u2028 \xff\" }")
	c := appendCompact(nil, raw)
	if bytes.ContainsAny(c, " \n\t") && !bytes.Contains(c, []byte("x y")) || len(c) > compactBound(len(raw)) {
		t.Errorf("compact: %q", c)
	}
	if string(c) != `{"a":[1,2],"b":"x y\n\" \u2028 \ufffd"}` {
		t.Errorf("compact: %s", c)
	}
	if !json.Valid(c) {
		t.Error("compact output not valid")
	}
}
