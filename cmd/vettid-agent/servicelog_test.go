package main

import (
	"errors"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"
)

type recordSink struct{ lines []string }

func (r *recordSink) Info(_ uint32, m string) error    { r.lines = append(r.lines, "I "+m); return nil }
func (r *recordSink) Warning(_ uint32, m string) error { r.lines = append(r.lines, "W "+m); return nil }
func (r *recordSink) Error(_ uint32, m string) error   { r.lines = append(r.lines, "E "+m); return nil }

// The cap cuts on a character's boundary, never inside one.
func TestCapValueUTF8(t *testing.T) {
	for _, v := range []string{
		strings.Repeat("a", maxLogValue-1) + "é",  // é straddles the cap
		strings.Repeat("a", maxLogValue-2) + "€x", // a 3-byte rune across it
		strings.Repeat("ü", 40),
		strings.Repeat("a", maxLogValue),
	} {
		c := capValue(v)
		if !utf8.ValidString(c) {
			t.Fatalf("capValue(%q) = %q, not valid UTF-8", v, c)
		}
		body := strings.TrimSuffix(c, "...")
		if len(body) > maxLogValue || !strings.HasPrefix(v, body) {
			t.Fatalf("capValue(%q) = %q", v, c)
		}
		if len(v) <= maxLogValue && c != v {
			t.Fatalf("capValue cut %q", v)
		}
	}
}

// The Event Log's line for each refusal: the code's fixed text; for 103
// also the privileges' names.
func TestRefusalMessage(t *testing.T) {
	m := refusalMessage(103, []string{"SeImpersonatePrivilege", "SeCreateGlobalPrivilege"})
	if m != "the service refuses to run: "+serviceRefusalText(103)+": SeImpersonatePrivilege, SeCreateGlobalPrivilege" {
		t.Fatalf("103: %q", m)
	}
	if m := refusalMessage(104, []string{"ignored"}); m != "the service refuses to run: "+serviceRefusalText(104) {
		t.Fatalf("104: %q", m)
	}
	sink := &recordSink{}
	slog.New(&eventLogHandler{sink: sink, name: "work"}).Error(refusalMessage(103, []string{"SeTcbPrivilege"}), "code", uint32(103))
	if len(sink.lines) != 1 || sink.lines[0] != "E pairing work: the service refuses to run: "+serviceRefusalText(103)+": SeTcbPrivilege code=103" {
		t.Fatalf("logged %q", sink.lines)
	}
}

// The Event Log gets the pairing's name, the message and the allowed
// attributes only: never an error's text, a grant, a path or a SID.
func TestEventLogHandlerAllowlist(t *testing.T) {
	sink := &recordSink{}
	log := slog.New(&eventLogHandler{sink: sink, name: "work"})
	secretish := `\\.\pipe\vettid-agent-work-0123456789abcdef0123456789abcdef S-1-5-21-1-2-3-1001 C:\ProgramData\VettID\agent\work`
	log.Warn("the MCP session ended", "err", errors.New(secretish), "grant", "g-123", "code", "session_required")
	log.With("err", secretish).Info("tool call", "tool", "leash.list_available", "outcome", "ok")
	log.Info("long", "code", strings.Repeat("x", 100))
	log.Error("the service refuses to run: x", "code", uint32(111), "path", secretish)
	log.Debug("not logged", "op", "mcp")
	want := []string{
		"W pairing work: the MCP session ended code=session_required",
		"I pairing work: tool call tool=leash.list_available outcome=ok",
		"I pairing work: long code=" + strings.Repeat("x", maxLogValue) + "...",
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
