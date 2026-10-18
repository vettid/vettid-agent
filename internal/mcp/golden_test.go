package mcp

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/leash/request"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// TestGolden: each message the server writes for a request is compared
// with its golden file (testdata/golden/NAME.json, indented); go test
// -run TestGolden -update rewrites them. The values in them are fake.
func TestGolden(t *testing.T) {
	initLine := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	callLine := func(name, args string) string {
		return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
	}
	until := time.Date(2026, 10, 18, 12, 10, 0, 0, time.UTC)
	cases := []struct {
		name    string
		noInit  bool
		line    string
		setup   func(f *fakeRequests)
		options func(o *Options)
	}{
		{name: "initialize", noInit: true, line: initLine},
		{name: "initialize_other_version", noInit: true, line: `{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2099-01-01","capabilities":{}}}`},
		{name: "tools_list", line: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{name: "list_available", line: callLine(ToolListAvailable, `{}`)},
		{name: "list_available_empty", line: callLine(ToolListAvailable, `{}`), setup: func(f *fakeRequests) {
			f.catalog = func() (*request.Outcome, error) {
				return &request.Outcome{Result: &request.Result{Op: request.OpCatalog, Catalog: []request.CatalogItem{}}}, nil
			}
		}},
		{name: "request_secret", line: callLine(ToolRequestSecret, `{"item_id":"`+testItem+`"}`)},
		{name: "request_secret_pending", line: callLine(ToolRequestSecret, `{"item_id":"`+testItem+`","fields":["password"]}`), setup: func(f *fakeRequests) {
			f.get = func(string, []string) (*request.Outcome, error) {
				return &request.Outcome{Pending: true, RequestID: testRequest, Waiting: true, Text: request.TextWaiting}, nil
			}
		}},
		{name: "request_secret_access_requested", line: callLine(ToolRequestSecret, `{"item_id":"`+testItem+`"}`), setup: func(f *fakeRequests) {
			f.get = func(string, []string) (*request.Outcome, error) {
				return nil, &request.Error{Code: access.ErrAccessRequested.Code, Text: access.ErrAccessRequested.Text}
			}
		}},
		{name: "request_secret_access_denied_quiet", line: callLine(ToolRequestSecret, `{"item_id":"`+testItem+`"}`), setup: func(f *fakeRequests) {
			f.get = func(string, []string) (*request.Outcome, error) {
				return nil, &request.Error{Code: access.ErrAccessDenied.Code, Text: access.ErrAccessDenied.Text, Until: until}
			}
		}},
		{name: "request_secret_forbidden", line: callLine(ToolRequestSecret, `{"item_id":"`+testItem+`"}`), setup: func(f *fakeRequests) {
			f.get = func(string, []string) (*request.Outcome, error) { return nil, request.ErrForbidden }
		}},
		{name: "request_secret_owner_check", line: callLine(ToolRequestSecret, `{"item_id":"`+testItem+`"}`), setup: func(f *fakeRequests) {
			f.get = func(string, []string) (*request.Outcome, error) { return nil, request.ErrOwnerCheck }
		}},
		{name: "request_secret_bad_arguments", line: callLine(ToolRequestSecret, `{"item":"x"}`)},
		{name: "execute_action", line: callLine(ToolExecuteAction, `{"item_id":"`+testItem+`","field_id":"password","data":"hello"}`)},
		{name: "execute_action_bad_base64", line: callLine(ToolExecuteAction, `{"item_id":"`+testItem+`","field_id":"password","data":"%%%","data_encoding":"base64"}`)},
		{name: "check_status_result", line: callLine(ToolCheckStatus, `{"request_id":"`+testRequest+`"}`), setup: func(f *fakeRequests) {
			f.status = func(string) (*request.Outcome, error) { return &request.Outcome{Result: fakeItem()}, nil }
		}},
		{name: "check_status_pending", line: callLine(ToolCheckStatus, `{"request_id":"`+testRequest+`"}`), setup: func(f *fakeRequests) {
			f.status = func(string) (*request.Outcome, error) {
				return &request.Outcome{Pending: true, RequestID: testRequest, Text: request.TextInFlight}, nil
			}
		}},
		{name: "check_status_denied", line: callLine(ToolCheckStatus, `{"request_id":"`+testRequest+`"}`), setup: func(f *fakeRequests) {
			f.status = func(string) (*request.Outcome, error) { return nil, request.ErrDenied }
		}},
		{name: "check_status_approval_timeout", line: callLine(ToolCheckStatus, `{"request_id":"`+testRequest+`"}`), setup: func(f *fakeRequests) {
			f.status = func(string) (*request.Outcome, error) { return nil, request.ErrTimeout }
		}},
		{name: "check_status_expired", line: callLine(ToolCheckStatus, `{"request_id":"`+testRequest+`"}`)},
		{name: "check_status_unreachable", line: callLine(ToolCheckStatus, `{"request_id":"`+testRequest+`"}`), setup: func(f *fakeRequests) {
			f.status = func(id string) (*request.Outcome, error) {
				return nil, &request.Error{Code: request.ErrUnreachable.Code, Text: request.ErrUnreachable.Text, RequestID: id}
			}
		}},
		{name: "connection_info", line: callLine(ToolConnectionInfo, `{}`), options: func(o *Options) { o.Held = func() bool { return true } }},
		{name: "rate_limited", line: callLine(ToolListAvailable, `{}`), options: func(o *Options) { o.Burst = 1 }},
		{name: "error_parse", noInit: true, line: `{"jsonrpc":`},
		{name: "error_batch", line: `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`},
		{name: "error_not_initialized", noInit: true, line: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{name: "error_method", line: `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}`},
		{name: "error_unknown_tool", line: callLine("leash.unknown", `{}`)},
		{name: "error_id", line: `{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`},
		{name: "ping", noInit: true, line: `{"jsonrpc":"2.0","id":"p","method":"ping"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRequests{}
			if tc.setup != nil {
				tc.setup(f)
			}
			s := newSession(t, f, tc.options)
			if !tc.noInit {
				s.init()
			}
			if tc.name == "rate_limited" {
				s.toolCall(6, ToolConnectionInfo, `{}`) // takes the one token
			}
			s.send(tc.line)
			raw := s.recvRaw()
			if bytes.Count(raw, []byte("\n")) != 1 || raw[len(raw)-1] != '\n' {
				t.Fatalf("not one line: %q", raw)
			}
			var ind bytes.Buffer
			if err := json.Indent(&ind, bytes.TrimSpace(raw), "", "  "); err != nil {
				t.Fatalf("not JSON: %q", raw)
			}
			ind.WriteByte('\n')
			path := filepath.Join("testdata", "golden", tc.name+".json")
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, ind.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
			if !bytes.Equal(ind.Bytes(), want) {
				t.Errorf("%s differs:\n got: %s\nwant: %s", path, ind.Bytes(), want)
			}
		})
	}
}
