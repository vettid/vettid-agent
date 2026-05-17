package fingerprint

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// SECURITY (#115): trusted directories an external fingerprint command
// must live in for safeCommand to return its path. Anything resolved
// outside this set — e.g. a malicious binary planted earlier on
// $PATH — is rejected. The set covers the locations OS package
// managers ship the commands we use (lsblk, ioreg, sysctl, diskutil)
// across Linux + macOS.
var trustedExecDirs = map[string]bool{
	"/usr/bin":      true,
	"/usr/sbin":    true,
	"/bin":          true,
	"/sbin":         true,
	"/usr/local/bin":  true,
	"/usr/local/sbin": true,
}

var (
	execPathCache   sync.Map // map[string]string — resolved → absolute path
	execLookupMu    sync.Mutex
)

// safeCommand resolves `name` via exec.LookPath and refuses paths
// outside trustedExecDirs. Returns an *exec.Cmd ready to run, or an
// error suitable for surfacing.
//
// Why: collect-machine-fingerprint code shells out to system tools
// (lsblk, ioreg, sysctl) by bare name. Without resolution we'd inherit
// whatever the agent's $PATH points to first, including attacker-
// planted shadows in user-writable dirs ($HOME/bin, /tmp/...). Pinning
// to system dirs eliminates the PATH-hijack class without needing a
// hardcoded absolute-path matrix per OS.
func safeCommand(name string, args ...string) (*exec.Cmd, error) {
	resolved, err := lookupTrusted(name)
	if err != nil {
		return nil, err
	}
	return exec.Command(resolved, args...), nil
}

func lookupTrusted(name string) (string, error) {
	if cached, ok := execPathCache.Load(name); ok {
		return cached.(string), nil
	}

	execLookupMu.Lock()
	defer execLookupMu.Unlock()
	// Re-check under lock.
	if cached, ok := execPathCache.Load(name); ok {
		return cached.(string), nil
	}

	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("locate %s in $PATH: %w", name, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("absolute path for %s: %w", name, err)
	}
	dir := filepath.Dir(abs)
	if !trustedExecDirs[dir] {
		return "", fmt.Errorf(
			"refusing %s — resolved to %s but %s is not in trustedExecDirs (set $PATH to a known system dir)",
			name, abs, dir,
		)
	}
	// Defensive: refuse any symlink target that resolves outside the
	// trusted set (an attacker who can create a symlink in /usr/bin
	// is already root; this is the floor).
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		resolvedDir := filepath.Dir(resolved)
		if !trustedExecDirs[resolvedDir] && !strings.HasPrefix(resolvedDir, "/usr/lib") {
			return "", fmt.Errorf(
				"refusing %s — symlink at %s targets %s (outside trustedExecDirs)",
				name, abs, resolved,
			)
		}
	}
	execPathCache.Store(name, abs)
	return abs, nil
}
