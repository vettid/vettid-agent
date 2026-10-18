//go:build devstack

package devstack

// The member's app is the dev stack's `vaultctl` (AGENT-PLAN §4.8;
// vettid-vault README, "A member for an agent"), on a test vault of its
// own enrolled through the member API stand-in.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TEST-ONLY credentials of the test vaults (the vettid-vault README's).
const (
	testPassword = "development password"
	testPIN      = "13572468"
)

// Event is an event the member's app received.
type Event struct {
	Type string          `json:"type"`
	ID   string          `json:"id"`
	Re   string          `json:"re"`
	Body json.RawMessage `json:"body"`
}

// Member is the member's app.
type Member struct {
	t     *testing.T
	s     *Stack
	bin   string
	state string
	GUID  string

	mu     sync.Mutex
	events []Event // received and not yet taken
}

// newMember enrolls a fresh test vault with its own vaultctl app: init,
// api-enroll (which also creates the credential), and opens the
// credential's unlock window.
func newMember(ctx context.Context, t *testing.T, s *Stack) *Member {
	t.Helper()
	var r [6]byte
	_, _ = rand.Read(r[:])
	m := &Member{t: t, s: s, bin: filepath.Join(s.Data, "bin", "vaultctl"),
		state: filepath.Join(t.TempDir(), "member.json"), GUID: "agent-devstack-" + hex.EncodeToString(r[:])}
	m.must(ctx, "init", "-role", "app", "-name", "member-phone", "-relay", s.RelayURL)
	m.must(ctx, "api-enroll", "-api", s.API, "-guid", m.GUID, "-pin", testPIN)
	m.unlock(ctx)
	return m
}

// run runs vaultctl and returns its standard output; a failure carries
// its standard error (vaultctl's "error <code>").
func (m *Member) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, m.bin, append([]string{"-state", m.state, "-timeout", "150s"}, args...)...)
	cmd.Env = append(os.Environ(),
		"VAULTCTL_DEV_RESOLVE=relay.vettid.test="+m.s.RelayTLS,
		"VAULTCTL_PASSWORD="+testPassword, "VAULTCTL_PIN="+testPIN)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("vaultctl %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func (m *Member) must(ctx context.Context, args ...string) []byte {
	m.t.Helper()
	out, err := m.run(ctx, args...)
	if err != nil {
		m.t.Fatal(err)
	}
	return out
}

// objects splits vaultctl's output into its JSON objects (it prints them
// indented, one after the other); text lines ("ok") are skipped.
func objects(out []byte) []json.RawMessage {
	var objs []json.RawMessage
	for len(bytes.TrimSpace(out)) > 0 {
		i := bytes.IndexByte(out, '{')
		if i < 0 {
			break
		}
		dec := json.NewDecoder(bytes.NewReader(out[i:]))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			break
		}
		objs = append(objs, raw)
		out = out[i+int(dec.InputOffset()):]
	}
	return objs
}

// obj runs a vaultctl command that prints one JSON object.
func (m *Member) obj(ctx context.Context, args ...string) map[string]json.RawMessage {
	m.t.Helper()
	out := m.must(ctx, args...)
	objs := objects(out)
	if len(objs) == 0 {
		m.t.Fatalf("vaultctl %s printed no object: %q", args[0], out)
	}
	var o map[string]json.RawMessage
	if err := json.Unmarshal(objs[0], &o); err != nil {
		m.t.Fatalf("vaultctl %s: %v", args[0], err)
	}
	return o
}

// Response is a vault response as `vaultctl request` prints it.
type Response struct {
	Status string          `json:"status"`
	Body   json.RawMessage `json:"body"`
	Error  string          `json:"error"`
}

// request sends a request; the events printed after the response are
// kept for waitEvent.
func (m *Member) request(ctx context.Context, typ, body string) Response {
	m.t.Helper()
	out := m.must(ctx, "request", typ, body)
	objs := objects(out)
	if len(objs) == 0 {
		m.t.Fatalf("vaultctl request %s printed nothing", typ)
	}
	var r Response
	if err := json.Unmarshal(objs[0], &r); err != nil {
		m.t.Fatalf("vaultctl request %s: %v", typ, err)
	}
	m.keep(objs[1:])
	return r
}

func (m *Member) keep(objs []json.RawMessage) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range objs {
		var ev Event
		if json.Unmarshal(o, &ev) == nil && ev.Type != "" {
			m.events = append(m.events, ev)
		}
	}
}

// take removes and returns the first kept event of type typ that match
// accepts.
func (m *Member) take(typ string, match func(json.RawMessage) bool) (Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, ev := range m.events {
		if ev.Type == typ && (match == nil || match(ev.Body)) {
			m.events = append(m.events[:i:i], m.events[i+1:]...)
			return ev, true
		}
	}
	return Event{}, false
}

// waitEvent collects events until one of type typ that match accepts
// arrives, or timeout.
func (m *Member) waitEvent(ctx context.Context, typ string, match func(json.RawMessage) bool, timeout time.Duration) Event {
	m.t.Helper()
	end := time.Now().Add(timeout)
	for {
		if ev, ok := m.take(typ, match); ok {
			return ev
		}
		if time.Now().After(end) {
			m.mu.Lock()
			var seen []string
			for _, ev := range m.events {
				seen = append(seen, ev.Type)
			}
			m.mu.Unlock()
			m.t.Fatalf("no %s event within %v (kept: %v)", typ, timeout, seen)
		}
		m.keep(objects(m.must(ctx, "events", "-wait", "3s")))
	}
}

// unlock opens the credential's unlock window, in which grants are
// signed.
func (m *Member) unlock(ctx context.Context) {
	m.t.Helper()
	m.obj(ctx, "credential", "unlock")
}

// putItem stores an item and returns its id.
func (m *Member) putItem(ctx context.Context, sensitivity, tags, content string) string {
	m.t.Helper()
	o := m.obj(ctx, "item", "put", "-sensitivity", sensitivity, "-tags", tags, "-content", content)
	return str(m.t, o, "item_id")
}

// fieldID returns the id of an item's field labelled label (item.get:
// the fields' ids and labels, without values).
func (m *Member) fieldID(ctx context.Context, item, label string) string {
	m.t.Helper()
	o := m.obj(ctx, "item", "get", "-id", item)
	var fields []struct {
		ID    string `json:"field_id"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(o["fields"], &fields); err != nil {
		m.t.Fatalf("item get %s: fields: %v", item, err)
	}
	for _, f := range fields {
		if f.Label == label && f.ID != "" {
			return f.ID
		}
	}
	m.t.Fatalf("item get %s: no field labelled %q", item, label)
	return ""
}

func keys(o map[string]json.RawMessage) []string {
	var ks []string
	for k := range o {
		ks = append(ks, k)
	}
	return ks
}

// str returns a string member of o.
func str(t *testing.T, o map[string]json.RawMessage, k string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(o[k], &s); err != nil || s == "" {
		t.Fatalf("no string %q in %s", k, keys(o))
	}
	return s
}

// field returns a string member of a JSON object.
func field(t *testing.T, b json.RawMessage, k string) string {
	t.Helper()
	var o map[string]json.RawMessage
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("not an object: %v", err)
	}
	return str(t, o, k)
}

// has matches an event body whose member k is the string v.
func has(k, v string) func(json.RawMessage) bool {
	return func(b json.RawMessage) bool {
		var o map[string]json.RawMessage
		if json.Unmarshal(b, &o) != nil {
			return false
		}
		var s string
		return json.Unmarshal(o[k], &s) == nil && s == v
	}
}
