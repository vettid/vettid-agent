package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vettid/vettid-agent/internal/leash"
)

// writeGrants prints the LEASH grants as last saved (internal/leash):
// scope, approval, limits, expiry and connections, never delegations or
// statements. Every string from the vault is printed through printable.
func writeGrants(w io.Writer, raw json.RawMessage, deviceID string, now time.Time) {
	s, err := leash.ReadSaved(raw, deviceID, now)
	switch {
	case err != nil:
		fmt.Fprintln(w, "Grants: the saved grants cannot be read (they are listed again from your vault when `vettid-agent mcp` next has access)")
		return
	case s == nil:
		fmt.Fprintln(w, "Grants: none saved yet (listed from your vault when `vettid-agent mcp` has access)")
		return
	}
	fmt.Fprintf(w, "Grants: %d, as your vault sent them on %s\n", len(s.Grants), s.AsOf.Local().Format("2006-01-02 15:04"))
	if s.Suspended {
		fmt.Fprintln(w, "  Paused by your vault after repeated refused requests: none can be used. You can resume this agent on your phone.")
	}
	for _, g := range s.Grants {
		fmt.Fprintf(w, "  %s: %s", printable(g.Scope), describeApproval(g.Approval))
		if g.PerHour > 0 {
			fmt.Fprintf(w, ", up to %d an hour and %d a day without asking", g.PerHour, g.PerDay)
		}
		if g.ExpiresAt != nil {
			fmt.Fprintf(w, ", until %s", g.ExpiresAt.Local().Format("2006-01-02 15:04"))
		}
		if len(g.Connections) > 0 {
			cs := make([]string, len(g.Connections))
			for i, c := range g.Connections {
				cs[i] = printable(c)
			}
			fmt.Fprintf(w, ", connections %s", strings.Join(cs, " "))
		}
		fmt.Fprintf(w, " (grant %s)\n", printable(g.GrantID))
	}
}

func describeApproval(a string) string {
	switch a {
	case "ask":
		return "asks on your phone"
	case "auto":
		return "allowed automatically"
	default:
		return printable(a)
	}
}

// printable keeps letters, digits and a few separators (at most 64),
// so that nothing from the vault can control the terminal.
func printable(s string) string {
	b := make([]byte, 0, 64)
	for i := 0; i < len(s) && len(b) < 64; i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.IndexByte("._- ", ch) >= 0 {
			b = append(b, ch)
		}
	}
	if len(b) == 0 {
		return "-"
	}
	return string(b)
}
