package request

import (
	"fmt"
	"log/slog"
)

// Item values must never reach a log or a formatted string by accident
// (AGENT-PLAN §4.7). Result, Item, Field and Use therefore format
// themselves, with every verb (%v, %+v, %#v, %s, %x, …), and log
// themselves through slog, as a summary: ids, kinds and sizes, never a
// value, a note or an HMAC. Only the MCP layer reads the values, member
// by member.

// String summarises the field without its value.
func (f Field) String() string {
	return fmt.Sprintf("Field{field_id: %q, kind: %q, value: %s}", f.FieldID, f.Kind, redacted(f.Value))
}

// Format writes String for every verb.
func (f Field) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(f.String())) }

// LogValue logs the field without its value.
func (f Field) LogValue() slog.Value {
	return slog.GroupValue(slog.String("field_id", f.FieldID), slog.String("kind", f.Kind),
		slog.Int("value_bytes", len(f.Value)))
}

// String summarises the item without its values and notes.
func (it Item) String() string {
	return fmt.Sprintf("Item{item_id: %q, fields: %d, notes: %s}", it.ItemID, len(it.Fields), redacted(it.Notes))
}

// Format writes String for every verb.
func (it Item) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(it.String())) }

// LogValue logs the item without its values and notes.
func (it Item) LogValue() slog.Value {
	return slog.GroupValue(slog.String("item_id", it.ItemID), slog.Int("fields", len(it.Fields)))
}

// String summarises the use without its HMAC.
func (u Use) String() string {
	return fmt.Sprintf("Use{item_id: %q, field_id: %q, action: %q, result: %s}", u.ItemID, u.FieldID, u.Action, redacted(u.Result))
}

// Format writes String for every verb.
func (u Use) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(u.String())) }

// LogValue logs the use without its HMAC.
func (u Use) LogValue() slog.Value {
	return slog.GroupValue(slog.String("item_id", u.ItemID), slog.String("field_id", u.FieldID),
		slog.String("action", u.Action))
}

// String summarises the result without values.
func (r Result) String() string {
	switch {
	case r.Item != nil:
		return fmt.Sprintf("Result{op: %q, item: %s}", r.Op, r.Item.String())
	case r.Use != nil:
		return fmt.Sprintf("Result{op: %q, use: %s}", r.Op, r.Use.String())
	default:
		return fmt.Sprintf("Result{op: %q, catalog: %d items}", r.Op, len(r.Catalog))
	}
}

// Format writes String for every verb.
func (r Result) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(r.String())) }

// LogValue logs the result without values.
func (r Result) LogValue() slog.Value {
	attrs := []slog.Attr{slog.String("op", r.Op)}
	switch {
	case r.Item != nil:
		attrs = append(attrs, slog.Any("item", r.Item.LogValue()))
	case r.Use != nil:
		attrs = append(attrs, slog.Any("use", r.Use.LogValue()))
	default:
		attrs = append(attrs, slog.Int("catalog", len(r.Catalog)))
	}
	return slog.GroupValue(attrs...)
}

func redacted(b []byte) string {
	if b == nil {
		return "absent"
	}
	return fmt.Sprintf("[redacted, %d bytes]", len(b))
}
