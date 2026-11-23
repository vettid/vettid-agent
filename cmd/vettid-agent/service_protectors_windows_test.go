//go:build windows

package main

import (
	"strings"
	"testing"
)

// The service pairs with the platform protector (DPAPI of its own
// account): its protectors must not read as a passphrase source given,
// which would refuse DPAPI and every pairing with it.
func TestServiceProtectorsPairWithDPAPI(t *testing.T) {
	p, notice, err := serviceProtectors(t.TempDir()).New()
	if err != nil {
		t.Fatalf("the service's protectors refused a new pairing: %v", err)
	}
	if p == nil {
		t.Fatal("no protector")
	}
	if !strings.Contains(notice, "DPAPI") {
		t.Errorf("notice %q does not name DPAPI", notice)
	}
}
