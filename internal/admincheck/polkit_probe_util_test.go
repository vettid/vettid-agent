package admincheck

// Pure helpers of the polkit probe (polkit_probe_linux_test.go), here so
// their tests run everywhere.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// parentOf is the ppid in /proc/<pid>/stat (field 4).
func parentOf(stat []byte) int {
	i := strings.LastIndexByte(string(stat), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(stat[i+2:]))
	if len(f) < 2 {
		return 0
	}
	v, _ := strconv.Atoi(f[1])
	return v
}

func startTimeOf(stat []byte) uint64 {
	i := strings.LastIndexByte(string(stat), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(stat[i+2:]))
	if len(f) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(f[19], 10, 64)
	return v
}

func TestProcStat(t *testing.T) {
	// a comm holding ") " must not shift the fields
	stat := []byte("4242 (a) b (c) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 0")
	if got := parentOf(stat); got != 17 {
		t.Errorf("ppid %d", got)
	}
	if got := startTimeOf(stat); got != 987654 {
		t.Errorf("start time %d", got)
	}
	if parentOf([]byte("junk")) != 0 || startTimeOf([]byte("1 (x) S")) != 0 {
		t.Error("short or broken stat lines should read as 0")
	}
}

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

// subset: every id of a (a set string) is in b.
func subset(a, b string) bool {
	in := map[string]bool{}
	for _, id := range strings.Fields(b) {
		in[id] = true
	}
	for _, id := range strings.Fields(a) {
		if !in[id] {
			return false
		}
	}
	return true
}

func TestSubset(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"", "10 1001", true}, {"1001", "10 1001", true}, {"10 1001", "10 1001", true}, {"10 1001 27", "10 1001", false}, {"5", "", false}} {
		if got := subset(c.a, c.b); got != c.want {
			t.Errorf("subset(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

// identityMap: a uid_map or gid_map that is the identity over every id
// ("0 0 4294967295"), as the first user namespace's is.
func identityMap(m string) bool {
	lines := strings.Split(strings.TrimSpace(m), "\n")
	if len(lines) != 1 {
		return false
	}
	f := strings.Fields(lines[0])
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}

func TestIdentityMap(t *testing.T) {
	for _, c := range []struct {
		m    string
		want bool
	}{
		{"         0          0 4294967295\n", true},
		{"0 0 4294967295", true},
		{"         0       1000          1\n         1     524288      65536\n", false},
		{"         0          0      65536\n", false},
		{"         0          1 4294967295\n", false},
		{"", false},
		{"0 0 4294967295\n0 0 4294967295\n", false},
	} {
		if got := identityMap(c.m); got != c.want {
			t.Errorf("%q: %v", c.m, got)
		}
	}
}
