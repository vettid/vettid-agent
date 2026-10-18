package mcp

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/vettid/vettid-agent/internal/leash/request"
)

// sdkSession connects the MCP Go SDK's client to a Server over pipes.
func sdkSession(t *testing.T, f *fakeRequests, version string) *sdk.ClientSession {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	srv := New(Options{Requests: f, Info: fakeInfo, Version: "test"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, inR, outW); outW.Close() }()
	client := sdk.NewClient(&sdk.Implementation{Name: "sdk-test", Version: "1"}, nil)
	cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ccancel()
	var opts *sdk.ClientSessionOptions
	if version != "" {
		opts = &sdk.ClientSessionOptions{ProtocolVersion: version}
	}
	cs, err := client.Connect(cctx, &sdk.IOTransport{Reader: outR, Writer: inW}, opts)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		inW.Close()
		cancel()
		<-done
	})
	return cs
}

// callSDK calls a tool and returns its structured content (decoded) and
// isError; the text content must be the same JSON.
func callSDK(t *testing.T, cs *sdk.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("%s: %d content blocks", name, len(res.Content))
	}
	tc, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("%s: content %T", name, res.Content[0])
	}
	var fromText, fromStructured map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &fromText); err != nil {
		t.Fatalf("%s: text is not JSON: %v", name, err)
	}
	b, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(b, &fromStructured); err != nil {
		t.Fatalf("%s: structured content: %v", name, err)
	}
	tb, _ := json.Marshal(fromText)
	sb, _ := json.Marshal(fromStructured)
	if string(tb) != string(sb) {
		t.Errorf("%s: text and structured content differ:\n%s\n%s", name, tb, sb)
	}
	return fromStructured, res.IsError
}

// TestSDKClient: the MCP Go SDK's client negotiates a version, lists
// the five tools and calls each against the fake requests.
func TestSDKClient(t *testing.T) {
	for _, v := range []string{"", "2025-11-25", "2025-06-18", "2025-03-26"} {
		t.Run("version "+v, func(t *testing.T) {
			f := &fakeRequests{status: func(string) (*request.Outcome, error) { return nil, request.ErrDenied }}
			cs := sdkSession(t, f, v)
			got := cs.InitializeResult().ProtocolVersion
			want := v
			if v == "" {
				want = ProtocolVersions[0] // the SDK's newest falls back to initialize
			}
			if got != want {
				t.Errorf("negotiated %q, want %q", got, want)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			lt, err := cs.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, tl := range lt.Tools {
				names = append(names, tl.Name)
			}
			if !slices.Equal(names, []string{ToolListAvailable, ToolRequestSecret, ToolExecuteAction, ToolCheckStatus, ToolConnectionInfo}) {
				t.Fatalf("tools: %v", names)
			}

			sc, isErr := callSDK(t, cs, ToolListAvailable, nil)
			if isErr || len(sc["items"].([]any)) != 2 {
				t.Errorf("list_available: %v", sc)
			}
			sc, isErr = callSDK(t, cs, ToolRequestSecret, map[string]any{"item_id": testItem})
			fields, _ := sc["item"].(map[string]any)["fields"].([]any)
			if isErr || len(fields) != 4 || fields[1].(map[string]any)["value"] != testSecret {
				t.Errorf("request_secret: %v", sc)
			}
			sc, isErr = callSDK(t, cs, ToolExecuteAction, map[string]any{"item_id": testItem, "field_id": "password", "data": "hello"})
			if isErr || sc["result"] != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" {
				t.Errorf("execute_action: %v", sc)
			}
			sc, isErr = callSDK(t, cs, ToolCheckStatus, map[string]any{"request_id": testRequest})
			if !isErr || sc["code"] != "denied" || sc["message"] != request.TextDenied {
				t.Errorf("check_status: %v", sc)
			}
			sc, isErr = callSDK(t, cs, ToolConnectionInfo, nil)
			if isErr || sc["vault_id"] != "vault-test" || sc["waiting_for_daily_check"] != false {
				t.Errorf("connection_info: %v", sc)
			}
			if err := cs.Ping(ctx, nil); err != nil {
				t.Errorf("ping: %v", err)
			}
		})
	}
}
