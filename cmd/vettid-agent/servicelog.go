package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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
	"op":     true,
	"tool":   true,
	"type":   true,
	"code":   true,
	"result": true,
	"status": true,
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
			fmt.Fprintf(&b, " %s=%s", a.Key, a.Value.String())
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
