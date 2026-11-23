package admincheck

// Pure helpers of the polkit probe (polkit_probe_linux_test.go), here so
// their tests run everywhere.

import (
	"os"
	"path/filepath"
	"sort"
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

// statusUids: all four uids of a /proc/<pid>/status are uid.
func statusUids(st, uid string) bool {
	for _, line := range strings.Split(st, "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			ids := strings.Fields(rest)
			return len(ids) == 4 && ids[0] == uid && ids[1] == uid && ids[2] == uid && ids[3] == uid
		}
	}
	return false
}

// statusGroups: a /proc/<pid>/status's supplementary groups, sorted, as
// one string.
func statusGroups(st string) string {
	for _, line := range strings.Split(st, "\n") {
		if rest, ok := strings.CutPrefix(line, "Groups:"); ok {
			return set(strings.Fields(rest))
		}
	}
	return "none listed"
}

// hidepid: the /proc mount (from /proc/self/mountinfo) hides other
// users' processes, and its gid= option if any.
func hidepid(mountinfo string) (hidden bool, gid string) {
	for _, line := range strings.Split(mountinfo, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 5 || f[4] != "/proc" || len(g) < 3 || g[0] != "proc" {
			continue
		}
		hidden, gid = false, ""
		for _, o := range strings.Split(g[2], ",") {
			switch k, v, _ := strings.Cut(o, "="); k {
			case "hidepid":
				hidden = v != "0" && v != "off"
			case "gid":
				gid = v
			}
		}
	}
	return hidden, gid
}

func TestHidepid(t *testing.T) {
	const plain = "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
	for _, c := range []struct {
		mi     string
		hidden bool
		gid    string
	}{
		{plain, false, ""},
		{"22 1 0:21 / /proc rw,relatime shared:12 - proc proc rw,hidepid=invisible,gid=10\n", true, "10"},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=2\n", true, ""},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=noaccess\n", true, ""},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=0\n", false, ""},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=off\n", false, ""},
		// another proc mount elsewhere doesn't count; the last /proc does
		{"30 1 0:40 / /run/x/proc rw - proc proc rw,hidepid=2\n" + plain, false, ""},
		{plain + "40 22 0:50 / /proc rw - proc proc rw,hidepid=invisible\n", true, ""},
	} {
		if h, g := hidepid(c.mi); h != c.hidden || g != c.gid {
			t.Errorf("%q: %v %q", c.mi, h, g)
		}
	}
}

func TestStatusFields(t *testing.T) {
	st := "Name:\tsleep\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t10 1000 \n"
	if !statusUids(st, "1000") || statusUids(st, "100") || statusUids(strings.Replace(st, "1000\t1000\t1000\t1000\nGid", "1000\t0\t1000\t1000\nGid", 1), "1000") {
		t.Error("statusUids")
	}
	if g := statusGroups(st); g != set([]string{"10", "1000"}) {
		t.Errorf("statusGroups: %q", g)
	}
}

// set is a list of ids without duplicates, sorted, as one string.
func set(ids []string) string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}
