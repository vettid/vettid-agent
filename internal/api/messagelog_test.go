package api

import (
	"fmt"
	"testing"
	"time"
)

func TestMessageLog_RecentWindow(t *testing.T) {
	l := NewMessageLog()
	base := time.Date(2026, 5, 24, 20, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		l.Append(LoggedMessage{
			MessageID: fmt.Sprintf("m%d", i),
			Direction: directionFor(i),
			Content:   fmt.Sprintf("msg %d", i),
			SentAt:    base.Add(time.Duration(i) * time.Second),
		})
	}

	t.Run("default returns newest N oldest-first", func(t *testing.T) {
		got := l.Recent(5, "")
		want := []string{"m5", "m6", "m7", "m8", "m9"}
		assertIDs(t, got, want)
	})

	t.Run("before cursor returns strictly older messages", func(t *testing.T) {
		got := l.Recent(50, "m5")
		want := []string{"m0", "m1", "m2", "m3", "m4"}
		assertIDs(t, got, want)
	})

	t.Run("limit caps the page", func(t *testing.T) {
		got := l.Recent(2, "m5")
		// Two newest of m0..m4.
		want := []string{"m3", "m4"}
		assertIDs(t, got, want)
	})

	t.Run("before=oldest returns empty", func(t *testing.T) {
		got := l.Recent(50, "m0")
		if len(got) != 0 {
			t.Fatalf("expected empty page, got %v", ids(got))
		}
	})

	t.Run("unknown before falls through to newest window", func(t *testing.T) {
		got := l.Recent(3, "m-nonexistent")
		want := []string{"m7", "m8", "m9"}
		assertIDs(t, got, want)
	})

	t.Run("limit defaults to 50 when zero", func(t *testing.T) {
		got := l.Recent(0, "")
		// Only 10 messages logged; expect all of them.
		if len(got) != 10 {
			t.Fatalf("expected 10 messages, got %d", len(got))
		}
	})

	t.Run("limit clamps at 200", func(t *testing.T) {
		got := l.Recent(1000, "")
		// Only 10 messages logged; cap doesn't kick in but the call
		// shouldn't error or panic.
		if len(got) != 10 {
			t.Fatalf("expected 10 messages, got %d", len(got))
		}
	})
}

func TestMessageLog_BoundedCapacity(t *testing.T) {
	l := &MessageLog{cap: 5}
	base := time.Date(2026, 5, 24, 20, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		l.Append(LoggedMessage{
			MessageID: fmt.Sprintf("m%d", i),
			Direction: "incoming",
			SentAt:    base.Add(time.Duration(i) * time.Second),
		})
	}
	if l.Len() != 5 {
		t.Fatalf("expected log to be capped at 5, got %d", l.Len())
	}
	got := l.Recent(10, "")
	// Oldest 5 evicted; only m5..m9 survive.
	want := []string{"m5", "m6", "m7", "m8", "m9"}
	assertIDs(t, got, want)
}

func directionFor(i int) string {
	if i%2 == 0 {
		return "incoming"
	}
	return "outgoing"
}

func ids(msgs []LoggedMessage) []string {
	out := make([]string, len(msgs))
	for i, m := range msgs {
		out[i] = m.MessageID
	}
	return out
}

func assertIDs(t *testing.T, got []LoggedMessage, want []string) {
	t.Helper()
	gotIDs := ids(got)
	if len(gotIDs) != len(want) {
		t.Fatalf("got %v, want %v", gotIDs, want)
	}
	for i := range want {
		if gotIDs[i] != want[i] {
			t.Fatalf("got %v, want %v", gotIDs, want)
		}
	}
}
