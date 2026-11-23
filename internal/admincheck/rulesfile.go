package admincheck

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The rules file of AGENT-LINUX-RUNTIME §11.4: RulesFile's actions ask
// for an administrator for the VettID members it lists (one entry per
// pairing) and for a process of no account, and for no other account
// (the owner's a, GC #16962). @ENTRIES@ marks the list.
//
//go:embed testdata/40-vettid-agent.rules
var rulesTemplate string

// RulesEntry is one pairing's entry: its member's user name and the
// pairing's name.
type RulesEntry struct{ Member, Pairing string }

// A name the file may hold: a portable user name, and a pairing name of
// the same characters. Anything else is refused before it is written.
var rulesName = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._-]*$`)

const rulesIndent = "        "

// RenderRulesFile is the file for these entries, each member encoded as
// a JSON string (json.Marshal escapes quotes, backslashes, control
// characters and U+2028/2029) after its name is checked.
func RenderRulesFile(entries []RulesEntry) (string, error) {
	var lines []string
	for _, e := range entries {
		if !rulesName.MatchString(e.Member) || !rulesName.MatchString(e.Pairing) {
			return "", fmt.Errorf("a name the rules file can't hold: %q (pairing %q)", e.Member, e.Pairing)
		}
		m, err := json.Marshal(e.Member)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("%s%s, // %s", rulesIndent, m, e.Pairing))
	}
	return strings.Replace(rulesTemplate, "@ENTRIES@", strings.Join(lines, "\n"), 1), nil
}

// ParseRulesFile reads the entries of a file this tool wrote. A file not
// exactly in that format (edited, or another tool's) is an error: it is
// then printed for an administrator, never rewritten.
func ParseRulesFile(text string) ([]RulesEntry, error) {
	pre, _, ok := strings.Cut(rulesTemplate, "@ENTRIES@")
	if !ok || !strings.HasPrefix(text, pre) {
		return nil, errors.New("the rules file isn't in this tool's format")
	}
	var entries []RulesEntry
	for _, line := range strings.Split(strings.TrimPrefix(text, pre), "\n") {
		name, pairing, ok := strings.Cut(strings.TrimPrefix(line, rulesIndent), ", // ")
		if !ok || !strings.HasPrefix(line, rulesIndent) {
			break
		}
		var m string
		if err := json.Unmarshal([]byte(name), &m); err != nil {
			return nil, errors.New("the rules file isn't in this tool's format")
		}
		entries = append(entries, RulesEntry{Member: m, Pairing: pairing})
	}
	if again, err := RenderRulesFile(entries); err != nil || again != text {
		return nil, errors.New("the rules file isn't in this tool's format")
	}
	return entries, nil
}

// WithPairing is the entries with this pairing's entry added, replacing
// its old one; two pairings for one member keep two entries.
func WithPairing(entries []RulesEntry, e RulesEntry) []RulesEntry {
	return append(WithoutPairing(entries, e.Pairing), e)
}

// WithoutPairing is the entries without this pairing's (forget); with
// none left, the file is removed.
func WithoutPairing(entries []RulesEntry, pairing string) []RulesEntry {
	var out []RulesEntry
	for _, e := range entries {
		if e.Pairing != pairing {
			out = append(out, e)
		}
	}
	return out
}
