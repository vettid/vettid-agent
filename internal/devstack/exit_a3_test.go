//go:build devstack

package devstack

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TEST-ONLY item values.
const (
	askValue  = "devstack-ask-value"
	autoValue = "devstack-auto-value"
	hmacKey   = "devstack-hmac-key"
	critValue = "devstack-critical-value"
)

func itemContent(name, value string) string {
	b, _ := json.Marshal(map[string]any{"name": name, "fields": []map[string]string{{"label": "Key", "kind": "password", "value": value}}})
	return string(b)
}

// catalogIDs returns the item ids of a leash.list_available result.
func catalogIDs(t *testing.T, out map[string]any) []string {
	t.Helper()
	items, ok := out["items"].([]any)
	if !ok {
		t.Fatalf("list_available: %v", out)
	}
	var ids []string
	for _, it := range items {
		m, _ := it.(map[string]any)
		id, _ := m["item_id"].(string)
		ids = append(ids, id)
	}
	return ids
}

// itemValue returns the value of the field labelled "Key", and its id,
// from a leash.request_secret result.
func itemValue(t *testing.T, out map[string]any) (value, fieldID string) {
	t.Helper()
	item, _ := out["item"].(map[string]any)
	fields, _ := item["fields"].([]any)
	for _, f := range fields {
		m, _ := f.(map[string]any)
		if m["label"] == "Key" {
			v, _ := m["value"].(string)
			id, _ := m["field_id"].(string)
			return v, id
		}
	}
	t.Fatalf("request_secret: no Key field: %v", out)
	return "", ""
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// pastCooldown waits out the vault's refusal cooldown for the agent's
// items scope after one refusal (VAULT-MESSAGING §10.11: 1 s after the
// first refusal; an allowed request clears it).
func pastCooldown() { time.Sleep(1500 * time.Millisecond) }

// a3Setup is a paired connector with a test vault, an access session of
// an hour, and the MCP session.
type a3Setup struct {
	m   *Member
	a   *Agent
	dev string
	c   *MCP
}

func setupA3(ctx context.Context, t *testing.T, s *Stack) *a3Setup {
	t.Helper()
	m := newMember(ctx, t, s)
	a, dev := pairAgent(ctx, t, s, m, 3600)
	c := a.mcp(ctx)
	c.waitInfo(ctx, "active", func(in map[string]any) bool { return in["access_session"] == "active" }, time.Minute)
	return &a3Setup{m: m, a: a, dev: dev, c: c}
}

// TestExitA3 is AGENT-PLAN §6 A3's exit test, with vaultctl as the app,
// except its last step (the hold), which is TestExitA3Hold.
func TestExitA3(t *testing.T) {
	s := devStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	x := setupA3(ctx, t, s)
	m, c, dev := x.m, x.c, x.dev

	ask := m.putItem(ctx, "secret", "agent-ask", itemContent("ask item", askValue))
	auto := m.putItem(ctx, "secret", "agent-auto", itemContent("auto item", autoValue))
	use := m.putItem(ctx, "secret", "agent-use", itemContent("hmac item", hmacKey))
	crit := m.putItem(ctx, "critical", "agent-ask,agent-auto,agent-use", itemContent("critical item", critValue))

	t.Log("an ask rule: list_available is empty until the member approves the item")
	m.unlock(ctx)
	rule := m.obj(ctx, "share", "set", "-agent", dev, "-tags", "agent-ask", "-mode", "ask")
	askRule := str(t, rule, "rule_id")
	out, isErr := c.call(ctx, "leash.list_available", nil)
	if isErr || len(catalogIDs(t, out)) != 0 {
		t.Fatalf("list_available before the approval: %v", out)
	}
	pend := m.obj(ctx, "share", "pending", "-agent", dev)
	if b, _ := json.Marshal(pend); !strings.Contains(string(b), ask) || strings.Contains(string(b), crit) {
		t.Fatalf("share pending: %s", b)
	}
	m.must(ctx, "share", "decide", "-rule", askRule, "-items", ask)
	out, isErr = c.call(ctx, "leash.list_available", nil)
	if ids := catalogIDs(t, out); isErr || !contains(ids, ask) || contains(ids, crit) || len(ids) != 1 {
		t.Fatalf("list_available after the approval: %v", out)
	}
	t.Log("request_secret returns the value")
	out, isErr = c.call(ctx, "leash.request_secret", map[string]any{"item_id": ask})
	if v, _ := itemValue(t, out); isErr || v != askValue {
		t.Fatalf("request_secret (ask rule, approved): %v", code(out))
	}

	t.Log("an auto rule within its limits answers at once; past per_hour the request is referred and approved")
	m.unlock(ctx)
	rule = m.obj(ctx, "share", "set", "-agent", dev, "-tags", "agent-auto", "-mode", "auto", "-per-hour", "2", "-per-day", "50")
	autoRule := str(t, rule, "rule_id")
	for i := range 2 {
		start := time.Now()
		out, isErr = c.call(ctx, "leash.request_secret", map[string]any{"item_id": auto})
		if v, _ := itemValue(t, out); isErr || v != autoValue {
			t.Fatalf("request_secret (auto rule) %d: %v", i, code(out))
		}
		if d := time.Since(start); d > 15*time.Second {
			t.Errorf("request_secret (auto rule) %d took %v", i, d)
		}
	}
	type result struct {
		out   map[string]any
		isErr bool
	}
	done := make(chan result, 1)
	go func() {
		o, e := c.call(ctx, "leash.request_secret", map[string]any{"item_id": auto})
		done <- result{o, e}
	}()
	ap := m.waitEvent(ctx, "approval.pending", has("device_id", dev), 2*time.Minute)
	m.obj(ctx, "approval", "decide", "-id", field(t, ap.Body, "approval_id"), "-approve=true")
	r := <-done
	out, isErr = r.out, r.isErr
	t.Logf("the referred request was approved (tool result: %s)", map[bool]string{true: "pending, then leash.check_status", false: "the item"}[code(out) == "pending"])
	if !isErr && code(out) == "pending" {
		rid, _ := out["request_id"].(string)
		for range 60 {
			out, isErr = c.call(ctx, "leash.check_status", map[string]any{"request_id": rid})
			if code(out) != "pending" {
				break
			}
			time.Sleep(time.Second)
		}
	}
	if v, _ := itemValue(t, out); isErr || v != autoValue {
		t.Fatalf("request_secret past per_hour, approved: %v", code(out))
	}

	t.Log("execute_action returns the HMAC the test computes")
	m.unlock(ctx)
	m.obj(ctx, "share", "set", "-agent", dev, "-tags", "agent-use", "-mode", "auto")
	out, isErr = c.call(ctx, "leash.request_secret", map[string]any{"item_id": use})
	v, fid := itemValue(t, out)
	if isErr || v != hmacKey {
		t.Fatalf("request_secret (hmac item): %v", code(out))
	}
	data := "devstack data to sign"
	out, isErr = c.call(ctx, "leash.execute_action", map[string]any{"item_id": use, "field_id": fid, "data": data})
	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(data))
	if want := base64.StdEncoding.EncodeToString(mac.Sum(nil)); isErr || out["result"] != want {
		t.Fatalf("execute_action: %v, want result %s", out, want)
	}

	t.Log("a critical item is never listed or readable")
	out, isErr = c.call(ctx, "leash.list_available", nil)
	if ids := catalogIDs(t, out); isErr || contains(ids, crit) || !contains(ids, ask) || !contains(ids, auto) || !contains(ids, use) {
		t.Fatalf("list_available: %v", out)
	}
	out, isErr = c.call(ctx, "leash.request_secret", map[string]any{"item_id": crit})
	if !isErr || code(out) != "forbidden" {
		t.Fatalf("request_secret (critical): %v", out)
	}
	pastCooldown()
	// The critical item's own field: forbidden comes from the critical
	// rule, not from a field of another item.
	out, isErr = c.call(ctx, "leash.execute_action", map[string]any{"item_id": crit, "field_id": m.fieldID(ctx, crit, "Key"), "data": data})
	if !isErr || code(out) != "forbidden" {
		t.Fatalf("execute_action (critical): %v", out)
	}
	pastCooldown()
	pastCooldown()

	t.Log("revoking a rule stops reads at once")
	m.must(ctx, "leash", "revoke", "-id", autoRule)
	out, isErr = c.call(ctx, "leash.request_secret", map[string]any{"item_id": auto})
	if !isErr || code(out) != "forbidden" {
		t.Fatalf("request_secret after the revocation: %v", out)
	}

	t.Log("a loop of refused requests suspends the connector; connection_info shows it")
	suspended, calls := false, 0
	for i := 0; i < 60 && !suspended; i++ {
		calls++
		out, _ = c.call(ctx, "leash.request_secret", map[string]any{"item_id": auto})
		switch code(out) {
		case "forbidden":
		case "suspended":
			suspended = true
		default:
			t.Fatalf("refused request %d: %v", i, out)
		}
		if !suspended && i >= 30 {
			time.Sleep(time.Second)
		}
	}
	in := c.waitInfo(ctx, "suspended", func(in map[string]any) bool { return in["suspended"] == true }, time.Minute)
	t.Logf("suspended after %d refused calls; connection_info: suspended=%v", calls, in["suspended"])
	out, isErr = c.call(ctx, "leash.request_secret", map[string]any{"item_id": ask})
	if !isErr || code(out) != "suspended" {
		t.Fatalf("request_secret while suspended: %v", out)
	}

	t.Log("leash.agent.resume restores it")
	m.must(ctx, "leash", "resume", "-agent", dev)
	c.waitInfo(ctx, "resumed", func(in map[string]any) bool { return in["suspended"] == false }, time.Minute)
	out, isErr = c.call(ctx, "leash.request_secret", map[string]any{"item_id": ask})
	if v, _ := itemValue(t, out); isErr || v != askValue {
		t.Fatalf("request_secret after the resume: %v", code(out))
	}

	t.Log("unlink: the connector wipes itself")
	if r := m.request(ctx, "device.unlink", `{"device_id":"`+dev+`"}`); r.Error != "" {
		t.Fatalf("device.unlink: %s", r.Error)
	}
	if code := waitExit(t, c); code != 1 {
		t.Errorf("mcp exit code after the unlink: %d, want 1", code)
	}
	x.a.assertWiped()
}

// waitExit waits for the connector to stop after an unlink and returns
// its exit code.
func waitExit(t *testing.T, c *MCP) int {
	t.Helper()
	end := time.Now().Add(2 * time.Minute)
	for !strings.Contains(c.Stderr.String(), "This agent was removed from your vault.") {
		if time.Now().After(end) {
			t.Fatalf("no unlink notice:\n%s", c.Stderr)
		}
		time.Sleep(time.Second)
	}
	return c.close()
}

// envHold enables TestExitA3Hold, which takes over an hour.
const envHold = "VETTID_DEVSTACK_HOLD"

// TestExitA3Hold is the last step of AGENT-PLAN §6 A3's exit test: the
// hold gives owner_check_required. The dev stack has no clock to move for
// the owner check (vettid-vault README, "Not reachable quickly: a held
// vault"): the shortest interval is one hour, so this test waits for the
// real deadline and takes over an hour. It runs only with
// VETTID_DEVSTACK_HOLD=1 (`make devstack-hold-test`), never in `make
// devstack-test`.
func TestExitA3Hold(t *testing.T) {
	if os.Getenv(envHold) != "1" {
		t.Skip("takes over an hour; set " + envHold + "=1 (make devstack-hold-test)")
	}
	s := devStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Minute)
	defer cancel()
	m := newMember(ctx, t, s)

	t.Log("the owner check interval set to one hour (the shortest), and a check done now")
	st := m.obj(ctx, "settings", "get")
	var version uint64
	if err := json.Unmarshal(st["version"], &version); err != nil {
		t.Fatalf("settings get: no version (%v)", keys(st))
	}
	m.obj(ctx, "settings", "set", fmt.Sprint(version), `{"owner_check.interval_seconds":3600}`)
	oc := m.obj(ctx, "owner-check")
	deadline, err := time.Parse(time.RFC3339, str(t, oc, "deadline"))
	if err != nil {
		t.Fatal(err)
	}
	var hold bool
	_ = json.Unmarshal(oc["hold"], &hold)
	t.Logf("owner check deadline %s (hold %v)", deadline.Format(time.RFC3339), hold)
	if !hold {
		t.Fatalf("the owner check does not hold the vault: %v", oc)
	}

	a, dev := pairAgent(ctx, t, s, m, 86400)
	c := a.mcp(ctx)
	c.waitInfo(ctx, "active", func(in map[string]any) bool { return in["access_session"] == "active" }, time.Minute)
	m.unlock(ctx)
	item := m.putItem(ctx, "secret", "agent-hold", itemContent("hold item", askValue))
	m.obj(ctx, "share", "set", "-agent", dev, "-tags", "agent-hold", "-mode", "auto")
	out, isErr := c.call(ctx, "leash.request_secret", map[string]any{"item_id": item})
	if v, _ := itemValue(t, out); isErr || v != askValue {
		t.Fatalf("request_secret before the deadline: %v", code(out))
	}

	wait := time.Until(deadline) + time.Minute
	t.Logf("waiting %v for the deadline", wait.Round(time.Second))
	select {
	case <-time.After(wait):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	end := time.Now().Add(20 * time.Minute)
	for {
		out, _ = c.call(ctx, "leash.request_secret", map[string]any{"item_id": item})
		if code(out) == "owner_check_required" {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("no owner_check_required 20 minutes past the deadline: %v", code(out))
		}
		time.Sleep(time.Minute)
	}
	t.Log("the held vault gives owner_check_required")
	if code := c.close(); code != 0 {
		t.Errorf("mcp exit code: %d", code)
	}
}
