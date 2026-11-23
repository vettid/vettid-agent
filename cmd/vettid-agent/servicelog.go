package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"
)

// eventSink is where the service's log goes: the Windows Event Log
// (*eventlog.Log), or a test's recorder.
type eventSink interface {
	Info(eid uint32, msg string) error
	Warning(eid uint32, msg string) error
	Error(eid uint32, msg string) error
}

// eventLogKeys are the only attributes the service's log passes on.
// Other users of the computer can read the system log, so it holds only
// the pairing's name, the operation or tool, and outcome codes
// (AGENT-SEPARATE-ACCOUNT §3 "Logs"): never an error's text (which can
// name the pipe, a path or a SID), a grant or a value.
var eventLogKeys = map[string]bool{
	"outcome": true,
	"op":      true,
	"tool":    true,
	"type":    true,
	"code":    true,
	"result":  true,
	"status":  true,
}

// maxLogValue bounds each attribute's value in the log (chosen; not in
// the spec): codes, tool names and types are short.
const maxLogValue = 64

// capValue cuts v to at most maxLogValue bytes, on a character's
// boundary: never inside a UTF-8 sequence.
func capValue(v string) string {
	if len(v) <= maxLogValue {
		return v
	}
	i := maxLogValue
	for i > 0 && !utf8.RuneStart(v[i]) {
		i--
	}
	return v[:i] + "..."
}

// refusalMessage is the Event Log's text for a refusal to start with
// code: the code's fixed text, and for a privilege refusal (103) the
// privileges' names, which are not sensitive and say what to cut.
func refusalMessage(code uint32, privileges []string) string {
	m := "the service refuses to run: " + serviceRefusalText(code)
	if code == 103 && len(privileges) > 0 {
		m += ": " + strings.Join(privileges, ", ")
	}
	return m
}

// eventLogHandler writes the service's log to sink under the pairing's
// name: the message, then the allowed attributes. The messages are the
// service's own fixed texts.
type eventLogHandler struct {
	sink  eventSink
	name  string
	attrs []slog.Attr
}

func (h *eventLogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *eventLogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	fmt.Fprintf(&b, "pairing %s: %s", h.name, r.Message)
	add := func(a slog.Attr) bool {
		if eventLogKeys[a.Key] {
			v := capValue(a.Value.String())
			fmt.Fprintf(&b, " %s=%s", a.Key, v)
		}
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)
	if h.sink == nil {
		return nil
	}
	const eventID = 1
	switch {
	case r.Level >= slog.LevelError:
		return h.sink.Error(eventID, b.String())
	case r.Level >= slog.LevelWarn:
		return h.sink.Warning(eventID, b.String())
	default:
		return h.sink.Info(eventID, b.String())
	}
}

func (h *eventLogHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &eventLogHandler{sink: h.sink, name: h.name, attrs: append(append([]slog.Attr(nil), h.attrs...), as...)}
}

func (h *eventLogHandler) WithGroup(string) slog.Handler { return h }
