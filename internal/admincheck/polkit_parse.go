package admincheck

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParsePkaction reads `pkaction --verbose` (LC_ALL=C): one block per
// action, "<id>:" then indented "key: value" lines, with the implicit
// authorizations and any annotations.
func ParsePkaction(out string) (map[string]Action, error) {
	actions := map[string]Action{}
	var cur *Action
	flush := func() {
		if cur != nil {
			actions[cur.ID] = *cur
		}
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			flush()
			cur = &Action{ID: strings.TrimSuffix(line, ":")}
			continue
		}
		if cur == nil {
			return nil, fmt.Errorf("pkaction: a line before any action: %q", line)
		}
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.TrimSpace(key) {
		case "implicit any":
			cur.Any = Default(val)
		case "implicit inactive":
			cur.Inactive = Default(val)
		case "implicit active":
			cur.Active = Default(val)
		case "annotation":
			k, v, ok := strings.Cut(val, "->")
			switch k = strings.TrimSpace(k); {
			case !ok:
			case k == "org.freedesktop.policykit.exec.path":
				cur.ExecPath = strings.TrimSpace(v)
			case k == "org.freedesktop.policykit.exec.argv1":
				cur.ExecArgv1 = strings.TrimSpace(v)
			case k == "org.freedesktop.policykit.imply":
				// split on single spaces, as polkitd does (g_strsplit)
				// pkaction prints "<key> -> <value>"
				for _, id := range strings.Split(strings.TrimPrefix(v, " "), " ") {
					if id != "" {
						cur.Implies = append(cur.Implies, id)
					}
				}
			}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for id, a := range actions {
		for _, d := range []Default{a.Any, a.Inactive, a.Active} {
			switch d {
			case No, Yes, AuthSelf, AuthSelfKeep, AuthAdmin, AuthAdminKeep:
			default:
				return nil, fmt.Errorf("pkaction: %s has an unknown default %q", id, d)
			}
		}
	}
	return actions, nil
}

var gdbusAnswer = regexp.MustCompile(`^\(\((true|false), (true|false), (?:@a\{ss\} )?\{(.*)\}\),\)$`)

// ParseCheckAuthorization reads gdbus's printing of CheckAuthorization's
// reply, `((is_authorized, is_challenge, {details}),)`.
func ParseCheckAuthorization(out string) (authorized, challenge, temporary bool, err error) {
	m := gdbusAnswer.FindStringSubmatch(strings.TrimSpace(out))
	if m == nil {
		return false, false, false, fmt.Errorf("an answer it can't read: %q", strings.TrimSpace(out))
	}
	return m[1] == "true", m[2] == "true", strings.Contains(m[3], "'polkit.temporary_authorization_id'"), nil
}

// ParseBusctlCheck reads busctl's printing of CheckAuthorization's reply,
// `(bba{ss}) <authorized> <challenge> <n> "<key>" "<value>" ...`.
func ParseBusctlCheck(out string) (authorized, challenge, temporary bool, err error) {
	f, err := busctlFields(strings.TrimSpace(out))
	if err != nil {
		return false, false, false, err
	}
	if len(f) < 4 || f[0] != "(bba{ss})" || (f[1] != "true" && f[1] != "false") || (f[2] != "true" && f[2] != "false") {
		return false, false, false, fmt.Errorf("an answer it can't read: %q", out)
	}
	n, err := strconv.Atoi(f[3])
	if err != nil || n < 0 || len(f) != 4+2*n {
		return false, false, false, fmt.Errorf("an answer it can't read: %q", out)
	}
	for i := 0; i < n; i++ {
		if f[4+2*i] == "polkit.temporary_authorization_id" {
			temporary = true
		}
	}
	return f[1] == "true", f[2] == "true", temporary, nil
}

// busctlFields splits busctl's output on spaces, keeping double-quoted
// strings (with backslash escapes) whole and unquoted.
func busctlFields(s string) ([]string, error) {
	var out []string
	for i := 0; i < len(s); {
		switch {
		case s[i] == ' ':
			i++
		case s[i] == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(s) && s[j] != '"'; j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
			}
			if j >= len(s) {
				return nil, fmt.Errorf("an unterminated string in %q", s)
			}
			out = append(out, b.String())
			i = j + 1
		default:
			j := i
			for j < len(s) && s[j] != ' ' {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out, nil
}
