//go:build devstack

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vettid/vettid-agent/internal/devstack"
)

// A dev stack that cannot be reached ends `pair` and `mcp` through their
// normal return, with exit code 1, before the state directory is opened.
func TestDevstackUnreachable(t *testing.T) {
	// Not a loopback address: refused before anything is dialled.
	t.Setenv(devstack.EnvControl, "http://192.0.2.1:1")
	for _, name := range []string{"pair", "mcp"} {
		dir := filepath.Join(t.TempDir(), "state")
		var stdout, stderr bytes.Buffer
		if code := run([]string{name, "--state-dir", dir}, &stdout, &stderr); code != 1 {
			t.Errorf("%s: exit code %d, want 1 (stderr %q)", name, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "vettid-agent "+name+" (devstack build): "+devstack.EnvControl) {
			t.Errorf("%s: stderr %q", name, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: stdout %q", name, stdout.String())
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s: the state directory was created (%v)", name, err)
		}
	}
}
