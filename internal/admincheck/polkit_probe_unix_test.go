//go:build unix

package admincheck

// The polkit probe's helper that reads file owners (syscall.Stat_t), here
// so its test runs on every Unix but not on Windows.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The system folders a user manager reads drop-ins from.
var systemDropInRoots = []string{"/etc/systemd/user/", "/run/systemd/user/",
	"/usr/local/lib/systemd/user/", "/usr/lib/systemd/user/", "/usr/share/systemd/user/", "/lib/systemd/user/"}

// memberDropIns names a drop-in that isn't plainly the distribution's: it
// must lie under one of the system roots, and every component of its path
// from / must be a root-owned file or folder, not a symbolic link, and
// not writable by group or others. Anything else (the member's home, its
// runtime folder, a link) is named.
func memberDropIns(paths []string) string {
	for _, p := range paths {
		under := false
		for _, r := range systemDropInRoots {
			under = under || strings.HasPrefix(p, r)
		}
		if !under || filepath.Clean(p) != p {
			return p
		}
		for q := p; ; q = filepath.Dir(q) {
			fi, err := os.Lstat(q)
			if err != nil || fi.Mode()&os.ModeSymlink != 0 {
				return p
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
				return p
			}
			if q == "/" {
				break
			}
		}
	}
	return ""
}

func TestMemberDropIns(t *testing.T) {
	dir := t.TempDir()
	mine := filepath.Join(dir, "x.conf")
	if err := os.WriteFile(mine, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		mine,                                     // not under a system root
		"/etc/systemd/user/../../../tmp/x.conf",  // not clean
		"/etc/systemd/user/nonexistent.d/x.conf", // missing
	} {
		if memberDropIns([]string{p}) == "" {
			t.Errorf("%s: accepted", p)
		}
	}
	if memberDropIns(nil) != "" {
		t.Error("no drop-ins: refused")
	}
}
