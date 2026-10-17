package vettidagent_test

// The vault dependency (AGENT-PLAN §3.2, §6 A0.2): the connector builds on
// vettid-vault's reference client and its LEASH wire package at the commit
// pinned in go.mod and recorded in docs/SOURCE.md. This test fails to
// compile if either package moves or its exported API changes shape.

import (
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
