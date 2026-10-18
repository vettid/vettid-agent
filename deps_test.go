package vettidagent_test

// The vault dependency (AGENT-PLAN §3.2, §6 A0.2): the connector builds on
// vettid-vault's reference client and its LEASH wire package at the commit
// pinned in go.mod and recorded in docs/SOURCE.md. This test fails to
// compile if either package moves or its exported API changes shape.

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/leashwire"
)

func TestVaultPackagesCompile(t *testing.T) {
	// client: an agent device with fresh keys, without touching a relay,
	// survives a Save/Load round trip.
	cfg := client.Config{Role: "agent", Name: "compile test", RelayURL: "https://relay.vettid.test"}
	d, err := client.Generate(cfg)
	if err != nil {
		t.Fatalf("client.Generate: %v", err)
	}
	saved, err := d.Save()
	if err != nil || len(saved) == 0 {
		t.Fatalf("Save: %d bytes, %v", len(saved), err)
	}
	if _, err := client.Load(cfg, saved); err != nil {
		t.Fatalf("client.Load: %v", err)
	}

	// vms/leashwire: the reference verifier refuses an empty presentation.
	if _, err := leashwire.VerifyPresented(nil, &leashwire.Presented{}, time.Now()); err == nil {
		t.Fatal("leashwire.VerifyPresented accepted an empty presentation")
	}
}

// TestBinaryDoesNotLinkMCPSDK: the MCP Go SDK is used only by tests (its
// client drives the server); the binary's MCP server is internal/mcp
// and links none of it (docs/SOURCE.md).
func TestBinaryDoesNotLinkMCPSDK(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	out, err := exec.Command(gobin, "list", "-deps", "./cmd/vettid-agent").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, p := range strings.Fields(string(out)) {
		if strings.HasPrefix(p, "github.com/modelcontextprotocol/") {
			t.Errorf("the binary imports %s", p)
		}
	}
	if !strings.Contains(string(out), "github.com/vettid/vettid-agent/internal/mcp") {
		t.Error("the binary does not import internal/mcp")
	}
}

// TestDevstackOnlyWithTag: the dev-stack relay mapping (internal/devstack)
// is linked only into a build with the devstack tag, never into a
// default build (which release builds are); a devstack build links it,
// and still not the MCP Go SDK, which only the dev-stack tests use.
func TestDevstackOnlyWithTag(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command")
	}
	const devstack = "github.com/vettid/vettid-agent/internal/devstack"
	deps := func(args ...string) []string {
		out, err := exec.Command(gobin, append([]string{"list", "-deps"}, append(args, "./cmd/vettid-agent")...)...).Output()
		if err != nil {
			t.Fatalf("go list %v: %v", args, err)
		}
		return strings.Fields(string(out))
	}
	for _, p := range deps() {
		if p == devstack {
			t.Error("a build without the devstack tag imports internal/devstack")
		}
	}
	found := false
	for _, p := range deps("-tags", "devstack") {
		found = found || p == devstack
		if strings.HasPrefix(p, "github.com/modelcontextprotocol/") {
			t.Errorf("the devstack build imports %s", p)
		}
	}
	if !found {
		t.Error("the devstack build does not import internal/devstack")
	}
}
