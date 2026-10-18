//go:build windows

package protect

import (
	"os"
	"testing"
)

// TestDPAPIReachReal runs the real checks. CI's Windows runner is a
// local account with a local profile on a computer outside any domain,
// so both answer false; what matters most is that neither fails there.
func TestDPAPIReachReal(t *testing.T) {
	d, err := domainAccount()
	if err != nil {
		t.Fatalf("domain check: %v", err)
	}
	r, err := roamingProfile()
	if err != nil {
		t.Fatalf("roaming check: %v", err)
	}
	t.Logf("domain account: %v, roaming profile: %v", d, r)
	if _, err := profileTypeRoaming(); err != nil {
		t.Errorf("GetProfileType: %v", err)
	}
	if _, err := centralProfileSet(); err != nil {
		t.Errorf("ProfileList: %v", err)
	}
	// Elsewhere (a developer's domain computer) either may be true.
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return
	}
	if d || r {
		t.Errorf("on CI's runner: domain %v, roaming %v; want false, false", d, r)
	}
	if n := DPAPINotices(); len(n) != 0 {
		t.Errorf("notices on CI's runner: %q", n)
	}
}
