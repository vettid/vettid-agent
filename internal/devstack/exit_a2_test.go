//go:build devstack

package devstack

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

// pairAgent pairs a new connector with m's vault: device.pair.create
// (role agent), `vettid-agent pair` with the link, the SAS compared on
// both sides, and device.pair.approve with sessionSeconds. It returns
// the connector and its device id.
func pairAgent(ctx context.Context, t *testing.T, s *Stack, m *Member, sessionSeconds int) (*Agent, string) {
	t.Helper()
	a := newAgent(t, s)
	r := m.request(ctx, "device.pair.create", `{"role":"agent"}`)
	if r.Error != "" {
		t.Fatalf("device.pair.create: %s", r.Error)
	}
	link, pid := field(t, r.Body, "link"), field(t, r.Body, "pairing_id")
	p := a.pair(ctx, link)
	sas := p.sas(t)
	ev := m.waitEvent(ctx, "device.pair.pending", has("pairing_id", pid), 2*time.Minute)
	if got := field(t, ev.Body, "sas"); got != sas {
		t.Fatalf("SAS: the connector shows %s, the phone %s", sas, got)
	}
	if role := field(t, ev.Body, "role"); role != "agent" {
		t.Fatalf("device.pair.pending role %q", role)
	}
	m.unlock(ctx)
	body, _ := json.Marshal(map[string]any{"pairing_id": pid, "session_seconds": sessionSeconds})
	if r := m.request(ctx, "device.pair.approve", string(body)); r.Error != "" {
		t.Fatalf("device.pair.approve: %s", r.Error)
	}
	code, out := p.wait(t)
	if code != 0 || !strings.Contains(out, "Paired with your vault.") {
		t.Fatalf("pair: exit %d\n%s", code, out)
	}
	if st := a.status(ctx); !strings.Contains(st, "Paired") && !strings.Contains(st, "paired") {
		t.Fatalf("status after pairing:\n%s", st)
	}
	return a, agentDeviceID(ctx, t, m)
}

// agentDeviceID returns the device id of the vault's (one) agent device.
func agentDeviceID(ctx context.Context, t *testing.T, m *Member) string {
	t.Helper()
	r := m.request(ctx, "device.list", `{}`)
	var l struct {
		Devices []struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			State string `json:"state"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(r.Body, &l); err != nil {
		t.Fatalf("device.list: %v", err)
	}
	id := ""
	for _, d := range l.Devices {
		if d.Kind == "agent" && d.State == "active" {
			if id != "" {
				t.Fatalf("device.list: more than one agent")
			}
			id = d.ID
		}
	}
	if id == "" {
		t.Fatalf("device.list: no agent: %s", r.Body)
	}
	return id
}

var statusAnswered = regexp.MustCompile(`msg=response type=vault\.status .*ok=true`)

// TestExitA2 is AGENT-PLAN §6 A2's exit test: enroll a test vault with
// vaultctl, create and unlock its credential, pair the connector with
// session_seconds 600, compare the SAS on both sides, see vault.status
// answered, end the session from the app, request a new one and approve
// it, unlink, and see the connector wipe itself; a rejected pairing ends
// with "Rejected on your phone".
func TestExitA2(t *testing.T) {
	s := devStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	t.Log("enroll a test vault (api-enroll creates the credential) and unlock its credential")
	m := newMember(ctx, t, s)

	t.Log("pair with session_seconds 600; the SAS matches on both sides")
	a, dev := pairAgent(ctx, t, s, m, 600)

	t.Log("vault.status is answered; the first access session is active")
	c := a.mcp(ctx)
	if _, ok := c.Stderr.wait(statusAnswered, time.Minute); !ok {
		t.Fatalf("no vault.status answer:\n%s", c.Stderr)
	}
	in := c.waitInfo(ctx, "active", func(in map[string]any) bool { return in["access_session"] == "active" }, time.Minute)
	if in["device_id"] != dev || in["last_contact"] == nil {
		t.Fatalf("connection_info: %v (device %s)", in, dev)
	}

	t.Log("the app ends the session")
	m.must(ctx, "session", "end", "-device", dev)
	c.waitInfo(ctx, "ended", func(in map[string]any) bool { return in["access_session"] == "none" }, time.Minute)

	t.Log("a tool call asks for a new session; the app approves it")
	out, isErr := c.call(ctx, "leash.list_available", nil)
	if !isErr || code(out) != "access_requested" {
		t.Fatalf("list_available without a session: %v", out)
	}
	ev := m.waitEvent(ctx, "device.session.pending", has("device_id", dev), 2*time.Minute)
	if n := jsonInt(ev.Body, "seconds"); n != 3600 {
		t.Errorf("device.session.pending seconds %d, want 3600 (--access-minutes 60)", n)
	}
	m.obj(ctx, "session", "approve", "-id", field(t, ev.Body, "request_id"), "-seconds", "600")
	c.waitInfo(ctx, "active again", func(in map[string]any) bool { return in["access_session"] == "active" }, time.Minute)

	t.Log("unlink: the connector wipes itself")
	if r := m.request(ctx, "device.unlink", `{"device_id":"`+dev+`"}`); r.Error != "" {
		t.Fatalf("device.unlink: %s", r.Error)
	}
	if _, ok := c.Stderr.wait(regexp.MustCompile(regexp.QuoteMeta("This agent was removed from your vault. Its keys have been deleted from this computer.")), 2*time.Minute); !ok {
		t.Fatalf("no unlink notice:\n%s", c.Stderr)
	}
	if code := c.close(); code != 1 {
		t.Errorf("mcp exit code after the unlink: %d, want 1", code)
	}
	if st := a.status(ctx); !strings.Contains(st, "Not paired.") {
		t.Fatalf("status after the unlink:\n%s", st)
	}

	t.Log("a rejected pairing ends with \"Rejected on your phone.\"")
	b := newAgent(t, s)
	r := m.request(ctx, "device.pair.create", `{"role":"agent"}`)
	if r.Error != "" {
		t.Fatalf("device.pair.create: %s", r.Error)
	}
	pid := field(t, r.Body, "pairing_id")
	p := b.pair(ctx, field(t, r.Body, "link"))
	sas := p.sas(t)
	pend := m.waitEvent(ctx, "device.pair.pending", has("pairing_id", pid), 2*time.Minute)
	if got := field(t, pend.Body, "sas"); got != sas {
		t.Fatalf("SAS: the connector shows %s, the phone %s", sas, got)
	}
	if r := m.request(ctx, "device.pair.reject", `{"pairing_id":"`+pid+`"}`); r.Error != "" {
		t.Fatalf("device.pair.reject: %s", r.Error)
	}
	code, stderr := p.wait(t)
	if code != 1 || !strings.Contains(stderr, "Rejected on your phone.") {
		t.Fatalf("rejected pair: exit %d\n%s", code, stderr)
	}
	if st := b.status(ctx); !strings.Contains(st, "Not paired.") {
		t.Fatalf("status after the rejection:\n%s", st)
	}
}

// jsonInt returns a number member of a JSON object (0 if absent).
func jsonInt(b json.RawMessage, k string) int {
	var o map[string]json.RawMessage
	if json.Unmarshal(b, &o) != nil {
		return 0
	}
	var n int
	_ = json.Unmarshal(o[k], &n)
	return n
}
