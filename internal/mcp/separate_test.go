package mcp

import (
	"testing"

	"github.com/vettid/vettid-agent/internal/leash/request"
)

// Without its service, the stub lists the usual tools and answers every
// call with the refusal it was given; nothing is asked of a vault.
func TestUnavailable(t *testing.T) {
	for _, e := range []*request.Error{NoService(), VersionsDiffer()} {
		s := newSession(t, nil, func(o *Options) {
			// Nothing to ask: a call that reached a request would panic.
			o.Requests, o.Info = nil, nil
			o.Unavailable = e
		})
		s.init()
		s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		list := s.recv()
		tools, _ := list["result"].(map[string]any)["tools"].([]any)
		if len(tools) != len(New(Options{}).toolSet()) {
			t.Fatalf("tools/list: %v", list)
		}
		for i, tool := range []string{ToolListAvailable, ToolRequestSecret, ToolExecuteAction, ToolCheckStatus, ToolConnectionInfo} {
			args := `{}`
			switch tool {
			case ToolRequestSecret:
				args = `{"item_id":"01JAAAAAAAAAAAAAAAAAAAAAAA"}`
			case ToolExecuteAction:
				args = `{"item_id":"01JAAAAAAAAAAAAAAAAAAAAAAA","field_id":"f","data":""}`
			case ToolCheckStatus:
				args = `{"request_id":"r"}`
			}
			sc, isErr := s.toolCall(10+i, tool, args)
			if !isErr || sc["code"] != e.Code || sc["message"] != e.Text || sc["status"] != "error" {
				t.Fatalf("%s: %v (isError %v)", tool, sc, isErr)
			}
		}
	}
}
