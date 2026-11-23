package main

import (
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type recordSink struct{ lines []string }

func (r *recordSink) Info(_ uint32, m string) error    { r.lines = append(r.lines, "I "+m); return nil }
func (r *recordSink) Warning(_ uint32, m string) error { r.lines = append(r.lines, "W "+m); return nil }
func (r *recordSink) Error(_ uint32, m string) error   { r.lines = append(r.lines, "E "+m); return nil }

// The Event Log gets the pairing's name, the message and the allowed
// attributes only: never an error's text, a grant, a path or a SID.
func TestEventLogHandlerAllowlist(t *testing.T) {
	sink := &recordSink{}
	log := slog.New(&eventLogHandler{sink: sink, name: "work"})
	secretish := `\\.\pipe\vettid-agent-work-0123456789abcdef0123456789abcdef S-1-5-21-1-2-3-1001 C:\ProgramData\VettID\agent\work`
	log.Warn("the MCP session ended", "err", errors.New(secretish), "grant", "g-123", "code", "session_required")
	log.With("err", secretish).Info("tool answered", "tool", "leash.list_available", "result", "ok")
	log.Error("the service refuses to run: x", "code", uint32(111), "path", secretish)
	log.Debug("not logged", "op", "mcp")
	want := []string{
		"W pairing work: the MCP session ended code=session_required",
		"I pairing work: tool answered tool=leash.list_available result=ok",
		"E pairing work: the service refuses to run: x code=111",
	}
	if strings.Join(sink.lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("logged:\n%s\nwant:\n%s", strings.Join(sink.lines, "\n"), strings.Join(want, "\n"))
	}
	for _, l := range sink.lines {
		for _, never := range []string{"pipe", "S-1-5-21", "ProgramData", "g-123"} {
			if strings.Contains(l, never) {
				t.Fatalf("%q holds %q", l, never)
			}
		}
	}
}
