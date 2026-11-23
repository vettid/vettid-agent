package admincheck

// Pure helpers of the polkit probe (polkit_probe_linux_test.go), here so
// their tests run everywhere.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
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

// subgidRanges: the member's /etc/subgid ranges ([start, start+count)):
// lines owned by its name, its uid, or another name sameUser says has
// its uid. A line of the member's that isn't exactly name:start:count
// with plain decimal numbers (no sign, no leading zero) is an error.
func subgidRanges(content, name, uid string, sameUser func(string) bool) ([][2]uint64, error) {
	var out [][2]uint64
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		if f[0] != name && f[0] != uid && !sameUser(f[0]) {
			continue
		}
		if len(f) != 3 || !plainDecimal(f[1]) || !plainDecimal(f[2]) {
			return nil, fmt.Errorf("an /etc/subgid line it can't read: %s", line)
		}
		start, err1 := strconv.ParseUint(f[1], 10, 32)
		n, err2 := strconv.ParseUint(f[2], 10, 32)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("an /etc/subgid line it can't read: %s", line)
		}
		out = append(out, [2]uint64{start, start + n})
	}
	return out, nil
}

// plainDecimal: digits only, and no leading zero unless it is "0".
func plainDecimal(v string) bool {
	if v == "" || (len(v) > 1 && v[0] == '0') {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// groupsAccepted: a process's held groups, which aren't exactly the
// database's, are accepted: in the first user namespace only (sd-pam)
// holding none; outside it, fewer of the database's groups and gids
// inside the member's own subgid ranges (GC #16712, #16829), which rests
// on the overlap scan of the same ranges.
func groupsAccepted(held, want string, ranges [][2]uint64, firstNS, sdPam bool) bool {
	if firstNS {
		return sdPam
	}
	return subsetOrIn(held, want, ranges)
}

// subsetOrIn: every id of a is in b or inside one of the ranges.
func subsetOrIn(a, b string, ranges [][2]uint64) bool {
	in := map[string]bool{}
	for _, id := range strings.Fields(b) {
		in[id] = true
	}
	for _, id := range strings.Fields(a) {
		if in[id] {
			continue
		}
		g, err := strconv.ParseUint(id, 10, 32)
		ok := false
		for _, r := range ranges {
			ok = ok || (err == nil && g >= r[0] && g < r[1])
		}
		if !ok {
			return false
		}
	}
	return true
}

func TestGroupsAccepted(t *testing.T) {
	ranges := [][2]uint64{{524288, 589824}}
	want := "10 1001"
	for _, c := range []struct {
		held           string
		firstNS, sdPam bool
		ok             bool
	}{
		{"1001", true, false, false},               // first namespace: fewer refused
		{"10 1001 524288", true, false, false},     // first namespace: a subgid refused
		{"", true, true, true},                     // (sd-pam)
		{"", true, false, false},                   // none, not (sd-pam)
		{"1001", false, false, true},               // outside: fewer accepted
		{"1001 524288 524297", false, false, true}, // outside: subgids accepted
		{"1001 27", false, false, false},           // outside: another group refused
		{"1001 589824", false, false, false},       // outside: past the range
	} {
		if got := groupsAccepted(set(strings.Fields(c.held)), want, ranges, c.firstNS, c.sdPam); got != c.ok {
			t.Errorf("%q first=%v sdpam=%v: %v", c.held, c.firstNS, c.sdPam, got)
		}
	}
}

func TestSubgidRanges(t *testing.T) {
	none := func(string) bool { return false }
	r, err := subgidRanges("other:100000:65536\nmember:524288:65536\n1000:700000:10\n", "member", "1000", none)
	if err != nil || len(r) != 2 || r[0] != [2]uint64{524288, 589824} || r[1] != [2]uint64{700000, 700010} {
		t.Errorf("%v %v", r, err)
	}
	for _, bad := range []string{"member:x:1", "member:1:2:3", "member:1", "member:0100:5", "member:+1:5", "member:1:05", "1000::5", "alias:-1:5"} {
		alias := func(o string) bool { return o == "alias" }
		if _, err := subgidRanges(bad+"\n", "member", "1000", alias); err == nil {
			t.Errorf("%q read", bad)
		}
	}
	if r, err := subgidRanges("other:1:2:3\nmember:0:1\n", "member", "1000", none); err != nil || len(r) != 1 {
		t.Errorf("another's bad line, or a 0 start: %v %v", r, err)
	}
	alias := func(o string) bool { return o == "alias" }
	if r, err := subgidRanges("alias:800000:5\n", "member", "1000", alias); err != nil || len(r) != 1 || r[0] != [2]uint64{800000, 800005} {
		t.Errorf("another name with the member's uid: %v %v", r, err)
	}
	held := set([]string{"1001", "524288", "524297", "589823"})
	if !subsetOrIn(held, "10 1001", r) {
		t.Error("gids in the ranges refused")
	}
	if subsetOrIn(set([]string{"1001", "589824"}), "10 1001", r) || subsetOrIn("10 27", "1001", r) || subsetOrIn("x", "1001", r) {
		t.Error("a gid outside the ranges and the database accepted")
	}
	if !subsetOrIn("1001", "10 1001", nil) || subsetOrIn("524288", "10 1001", nil) {
		t.Error("without ranges: subset")
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

// hidepid: the hidepid mode of the /proc mount (from
// /proc/self/mountinfo; "" when none), and its gid= option ("0" when
// absent: the kernel's default, which mountinfo then doesn't print).
func hidepid(mountinfo string) (mode, gid string) {
	for _, line := range strings.Split(mountinfo, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 5 || f[4] != "/proc" || len(g) < 3 || g[0] != "proc" {
			continue
		}
		mode, gid = "", "0"
		for _, o := range strings.Split(g[2], ",") {
			switch k, v, _ := strings.Cut(o, "="); k {
			case "hidepid":
				mode = v
			case "gid":
				gid = v
			}
		}
	}
	if mode == "" {
		gid = ""
	}
	return mode, gid
}

// procHidden: a checker without CAP_SYS_PTRACE (the helper, the
// oneshot) can't see every process under that hidepid mode. Under
// 1/noaccess and 2/invisible the gid= group sees everything; under
// 4/ptraceable only ptrace access does, whatever the group.
func procHidden(mode, gid string, holds func(string) bool) bool {
	switch mode {
	case "", "0", "off":
		return false
	case "1", "noaccess", "2", "invisible":
		return !holds(gid)
	default: // 4, ptraceable, or a mode not known: fail closed
		return true
	}
}

func TestHidepid(t *testing.T) {
	const plain = "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
	for _, c := range []struct {
		mi        string
		mode, gid string
	}{
		{plain, "", ""},
		{"22 1 0:21 / /proc rw,relatime shared:12 - proc proc rw,hidepid=invisible,gid=10\n", "invisible", "10"},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=2\n", "2", "0"},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=1\n", "1", "0"},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,hidepid=ptraceable,gid=10\n", "ptraceable", "10"},
		{"22 1 0:21 / /proc rw,relatime - proc proc rw,gid=10\n", "", ""},
		{"30 1 0:40 / /run/x/proc rw - proc proc rw,hidepid=2\n" + plain, "", ""},
		{plain + "40 22 0:50 / /proc rw - proc proc rw,hidepid=invisible\n", "invisible", "0"},
	} {
		if m, g := hidepid(c.mi); m != c.mode || g != c.gid {
			t.Errorf("%q: %q %q", c.mi, m, g)
		}
	}
	root := func(g string) bool { return g == "0" }
	for _, c := range []struct {
		mode, gid string
		hidden    bool
	}{
		{"", "", false}, {"0", "0", false}, {"off", "0", false},
		{"2", "0", false}, {"invisible", "0", false}, {"noaccess", "0", false},
		{"2", "10", true}, {"1", "10", true}, {"invisible", "10", true},
		{"ptraceable", "0", true}, {"4", "0", true}, {"5", "0", true},
	} {
		if h := procHidden(c.mode, c.gid, root); h != c.hidden {
			t.Errorf("%s gid=%s: %v", c.mode, c.gid, h)
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
