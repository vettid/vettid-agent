package admincheck

import (
	"bufio"
	"fmt"
	"regexp"
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
			if k, v, ok := strings.Cut(val, "->"); ok && strings.TrimSpace(k) == "org.freedesktop.policykit.exec.path" {
				cur.ExecPath = strings.TrimSpace(v)
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
