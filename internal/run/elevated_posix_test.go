//go:build !windows

package run

import (
	"os"
	"testing"
)

// skipIfElevated: as root, every folder can be written, so a test of a
// protected folder can't hold.
func skipIfElevated(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: every folder can be changed")
	}
}
