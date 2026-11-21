package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-agent/internal/leash/request"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/mcp/stdio-session.txt")

// requestIDs are the vault's request ids in answers, which differ from run
// to run.
var requestIDs = regexp.MustCompile(`(\\?"request_id\\?":\\?")[0-9A-HJKMNP-TV-Z]{26}`)

// TestMCPStdioGolden: the bytes `vettid-agent mcp` writes to standard
// output for a fixed session against the fake vault, compared with
// testdata/mcp/stdio-session.txt at the repository root (request ids
// replaced by REQUEST_ID); go test -run TestMCPStdioGolden -update rewrites
// it. A change to how the session is run must leave them unchanged.
func TestMCPStdioGolden(t *testing.T) {
	v := newVault(t)
	dir := pairedDir(t, v)
	held := fakeAgentVault(t, v)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	withTestMCP(t, v, inR)
	mcpRequestOptions = func(o *request.Options) { o.Wait = 2 * time.Second }
	t.Cleanup(func() { mcpRequestOptions = nil })
	var errOut syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run([]string{"mcp", "--state-dir", dir}, outW, &errOut)
		outW.Close()
	}()
	out := bufio.NewReader(outR)
	var got bytes.Buffer
	// send writes one message and, unless it is a notification, reads its
	// answer.
	send := func(line string, answer bool) string {
		t.Helper()
		if _, err := io.WriteString(inW, line+"\n"); err != nil {
			t.Fatal(err)
		}
		if !answer {
			return ""
		}
		ch := make(chan string, 1)
		go func() { s, _ := out.ReadString('\n'); ch <- s }()
		select {
		case s := <-ch:
			got.WriteString(s)
			return s
		case <-time.After(20 * time.Second):
			t.Fatalf("no answer to %s (stderr %s)", line, errOut.String())
			return ""
		}
	}
	call := func(id, name, args string) string {
		return send(`{"jsonrpc":"2.0","id":`+id+`,"method":"tools/call","params":{"name":"`+name+`","arguments":`+args+`}}`, true)
	}
	send(`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"golden","version":"1"}}}`, true)
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, false)
	send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, true)
	call("2", "leash.list_available", `{}`)
	call("3", "leash.request_secret", `{"item_id":"`+toolItem+`"}`)
	call("4", "leash.execute_action", `{"item_id":"`+toolItem+`","field_id":"password","data":"Y2hhbGxlbmdl"}`)
	call("5", "leash.request_secret", `{"item_id":"`+referredItem+`","fields":["password"]}`)
	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("not held")
	}
	call("6", "leash.check_status", `{"request_id":"01JB2Z6V9K3M4N5P6Q7R8S9REQ"}`)
	call("7", "leash.request_secret", `{"item_id":"`+forbiddenItem+`"}`)
	call("8", "leash.no_such_tool", `{}`)
	send(`{"jsonrpc":"2.0","id":9,"method":"no/such/method"}`, true)
	send(`not json`, true)
	inW.Close()
	select {
	case rc := <-done:
		if rc != 0 {
			t.Fatalf("exit %d: %s", rc, errOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mcp did not exit")
	}
	rest, _ := io.ReadAll(out)
	got.Write(rest)
	norm := requestIDs.ReplaceAll(got.Bytes(), []byte("${1}REQUEST_ID"))
	path := filepath.Join("..", "..", "testdata", "mcp", "stdio-session.txt")
	if *updateGolden {
		if err := os.WriteFile(path, norm, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test -run TestMCPStdioGolden -update writes it)", err)
	}
	if !bytes.Equal(norm, want) {
		gl, wl := strings.Split(string(norm), "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) || i < len(wl); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("standard output differs at line %d\n got %s\nwant %s", i+1, g, w)
			}
		}
		t.Fatal("standard output differs")
	}
}
