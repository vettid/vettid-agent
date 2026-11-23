package admincheck

// The polkit measurement of AGENT-LINUX-RUNTIME §11.4 (card #16419): on a
// real system, as root, ask polkitd for every action it lists and every
// subject of the member's, judge the answers, print the result, and fail
// if the member would be refused. Run in a VM, never on a developer's
// machine:
//
//	sudo -E env VETTID_TEST_POLKIT_PROBE=<member> go test -run TestPolkitProbe -v ./internal/admincheck/
//
// It reads polkit with its own tools (pkaction, loginctl, systemd-run,
// gdbus), so it needs no D-Bus library.
//
// The rules file §11.4 describes, for the runs with it, is
// testdata/40-vettid-agent.rules (copied to /etc/polkit-1/rules.d/).

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// subject is one of the member's subjects, as polkit would judge it.
type subject struct {
	name string // for the report
	arg  string // gdbus's subject argument
	kind Kind
	// candidates: the kinds polkitd may judge it by, when they can't be
	// read beforehand; the one its answers match is taken (KindFrom).
	candidates []Kind
	// want: for a session subject, the kind worked out beforehand, which
	// its answers must confirm (KindFrom over every kind), or it is not
	// checked.
	want  *Kind
	pid   int
	start uint64
	uid   string
}

// sessionKind is the kind polkitd judges a logind session by. Its logind
// backend calls a session local when it has a seat (sd_session_get_seat),
// and active when the session's user is active (sd_uid_get_state: any of
// the user's sessions is active); a session that isn't local is judged by
// allow_any, whatever its state (polkitbackendinteractiveauthority.c).
// Remote isn't consulted.
func sessionKind(t *testing.T, id string) Kind {
	if seat := strings.TrimSpace(run(t, "loginctl", "show-session", id, "-p", "Seat", "--value")); seat == "" {
		return NoSession
	}
	uid := strings.TrimSpace(run(t, "loginctl", "show-session", id, "-p", "User", "--value"))
	if strings.TrimSpace(run(t, "loginctl", "show-user", uid, "-p", "State", "--value")) == "active" {
		return Active
	}
	return Inactive
}

// pidSession is the logind session a process belongs to, as logind says
// (sd_pid_get_session, through ps): a session scope's. The user's service
// manager and its units are in none (measured on systemd 258 and 259,
// where a manager-class session exists for them).
func pidSession(pid int) string {
	out, err := exec.Command("ps", "-o", "lsession=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return ""
	}
	if s := strings.TrimSpace(string(out)); s != "-" {
		return s
	}
	return ""
}

// sessionProcess is a process of the member's (all four uids) that logind
// places in the session, found in the cgroup of the session's leader and
// below it (the session scope). It needs the unified cgroup hierarchy
// (v2); on another, it finds none and the session is not checked.
func sessionProcess(t *testing.T, u *user.User, id string) int {
	leader := strings.TrimSpace(run(t, "loginctl", "show-session", id, "-p", "Leader", "--value"))
	b, err := os.ReadFile("/proc/" + leader + "/cgroup")
	if err != nil {
		t.Errorf("session %s: its leader: %v", id, err)
		return 0
	}
	_, cg, _ := strings.Cut(strings.TrimSpace(string(b)), "::")
	found := 0
	_ = filepath.WalkDir("/sys/fs/cgroup"+cg, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found != 0 || d.Name() != "cgroup.procs" {
			return nil
		}
		procs, _ := os.ReadFile(path)
		for _, f := range strings.Fields(string(procs)) {
			if pid, err := strconv.Atoi(f); err == nil && ownedBy(pid, u.Uid) && inSession(pid, id) {
				found = pid
				return fs.SkipAll
			}
		}
		return nil
	})
	return found
}

func ownedBy(pid int, uid string) bool {
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	return err == nil && statusUids(string(st), uid)
}

// inSession: logind's own answer (sd_pid_get_session, through ps).
func inSession(pid int, id string) bool { return pidSession(pid) == id }

// displaySession is the member's display session, if it is signed in.
func displaySession(name string) string {
	out, err := exec.Command("loginctl", "show-user", name, "-p", "Display").Output()
	if err != nil {
		return "" // not signed in
	}
	return strings.TrimSpace(strings.TrimPrefix(string(out), "Display="))
}

func startTime(t *testing.T, pid int) uint64 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+2:]))
	st, err := strconv.ParseUint(fields[19], 10, 64) // field 22 overall
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func subjects(t *testing.T, u *user.User) []subject {
	var out []subject
	// The candidate kinds for a process in no session: none, and the kind
	// of each of the member's sessions, read once here, before any of the
	// probe's own units start (one may open a transient session).
	cands := []Kind{NoSession}
	for _, line := range strings.Split(run(t, "loginctl", "list-sessions", "--no-legend"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == u.Uid {
			k := sessionKind(t, f[0])
			dup := false
			for _, c := range cands {
				dup = dup || c == k
			}
			if !dup {
				cands = append(cands, k)
			}
			// A manager-class session (systemd 258 and later: the user's
			// service manager) holds no process logind places in it, so
			// polkit judges none by it; its processes are asked as the user
			// service subject below.
			if class := strings.TrimSpace(run(t, "loginctl", "show-session", f[0], "-p", "Class", "--value")); strings.HasPrefix(class, "manager") {
				t.Logf("session %s: skipped (class %s)", f[0], class)
				continue
			}
			// Asked by a process of the member's in the session, which
			// polkit judges by that session: polkitd 124 and 127 abort on
			// a unix-session subject. (Not the leader: a tty session's
			// leader is login, running as root.)
			pid := sessionProcess(t, u, f[0])
			if pid == 0 {
				t.Errorf("session %s: not checked: no process of %s's in it", f[0], u.Username)
				continue
			}
			all := []Kind{k}
			for _, o := range []Kind{Active, Inactive, NoSession} {
				if o != k {
					all = append(all, o)
				}
			}
			out = append(out, subject{
				name:       fmt.Sprintf("session %s (pid %d)", f[0], pid),
				arg:        fmt.Sprintf("('unix-process', {'pid': <uint32 %d>, 'start-time': <uint64 %d>, 'uid': <int32 %s>})", pid, startTime(t, pid), u.Uid),
				kind:       k,
				candidates: all,
				want:       &k,
				pid:        pid,
				start:      startTime(t, pid),
				uid:        u.Uid,
			})
		}
	}
	// Processes of the member's in no session: a transient system service,
	// and a unit of the member's own service manager if it runs.
	if pid := sleeper(t, u, false); pid != 0 {
		out = append(out, noSession(t, u, "system service", pid, cands))
	} else {
		t.Fatal("the no-session process didn't start")
	}
	if exec.Command("systemctl", "is-active", "--quiet", "user@"+u.Uid+".service").Run() == nil {
		if pid := sleeper(t, u, true); pid != 0 {
			out = append(out, noSession(t, u, "user service", pid, cands))
		} else {
			t.Error("the user service didn't start: not checked")
		}
	} else {
		t.Logf("%s's service manager isn't running: no user service asked", u.Username)
	}
	return out
}

// sleeper starts a transient unit that sleeps, as the member, and
// returns its main pid, or 0 if it didn't start. A system service (the
// helper's child's kind: no_new_privs), or, with inManager, a unit of the
// member's own service manager, reached as §11.4 says: a system service
// as the member with no PAMName (so no session opens) talks to the
// manager's bus.
func sleeper(t *testing.T, u *user.User, inManager bool) int {
	unit := fmt.Sprintf("vettid-polkit-probe-%d", time.Now().UnixNano())
	var hop []string
	ctl := []string{"systemctl"}
	start := []string{"systemd-run", "--uid", u.Uid, "--gid", u.Gid, "--property=NoNewPrivileges=yes"}
	if inManager {
		rt := "/run/user/" + u.Uid
		// --wait, not --pipe (passing the caller's stdio through PID 1
		// is refused on Fedora 44); output goes to a file PID 1 writes.
		hop = []string{"systemd-run", "--uid", u.Uid, "--gid", u.Gid, "--wait", "--quiet", "--collect",
			"-E", "XDG_RUNTIME_DIR=" + rt, "-E", "DBUS_SESSION_BUS_ADDRESS=unix:path=" + rt + "/bus"}
		// Under SELinux the user bus refuses a system service's context
		// (Fedora 44, measured): the hop takes the member's manager's.
		if ctx := managerContext(u); ctx != "" {
			hop = append(hop, "--property=SELinuxContext="+ctx)
		}
		ctl = []string{"systemctl", "--user"}
		start = []string{"systemd-run", "--user"} // as an ordinary user service: no NoNewPrivileges
	}
	via := func(cmd ...string) *exec.Cmd {
		all := append(append([]string{}, hop...), cmd...)
		return exec.Command(all[0], all[1:]...)
	}
	// viaOut runs cmd through the hop and returns its standard output.
	viaOut := func(cmd ...string) string {
		if hop == nil {
			out, _ := exec.Command(cmd[0], cmd[1:]...).Output()
			return string(out)
		}
		f := fmt.Sprintf("/run/vettid-polkit-probe-%d.out", time.Now().UnixNano())
		defer os.Remove(f)
		all := append(append(append([]string{}, hop...), "--property=StandardOutput=file:"+f), cmd...)
		if err := exec.Command(all[0], all[1:]...).Run(); err != nil {
			return ""
		}
		b, _ := os.ReadFile(f)
		return string(b)
	}
	args := append(append([]string{}, start...), "--unit", unit, "--collect", "--property=RuntimeMaxSec=600", "/bin/sleep", "600")
	if out, err := via(args...).CombinedOutput(); err != nil {
		t.Logf("%s: %v\n%s", strings.Join(args, " "), err, out)
		return 0
	}
	t.Cleanup(func() { _ = via(append(append([]string{}, ctl...), "stop", unit)...).Run() })
	for i := 0; i < 50; i++ {
		out := viaOut(append(append([]string{}, ctl...), "show", "-p", "MainPID", "--value", unit)...)
		if pid, _ := strconv.Atoi(strings.TrimSpace(out)); pid != 0 {
			// The pid came back from a hop running as the member:
			// confirm it before asking polkitd (§11.4).
			// systemd 255 and later start a unit through
			// systemd-executor, which execs sleep a moment later: poll.
			if !confirmSleeper(pid, u, unit, inManager) {
				if i == 49 {
					t.Errorf("pid %d isn't the probe's own %s, unchanged: not checked", pid, unit)
					return 0
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if inManager {
				d := viaOut(append(append([]string{}, ctl...), "show", "-p", "DropInPaths", "--value", unit)...)
				if bad := memberDropIns(strings.Fields(d)); bad != "" {
					t.Errorf("the user service has a drop-in the member can write (%s): not checked", bad)
					return 0
				}
			}
			return pid
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0
}

// managerContext is the SELinux context of the member's service manager,
// where SELinux is enabled; else empty.
func managerContext(u *user.User) string {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); err != nil {
		return ""
	}
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", "user@"+u.Uid+".service").Output()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile("/proc/" + strings.TrimSpace(string(out)) + "/attr/current")
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\x00\n")
}

// confirmSleeper: the pid is the probe's own unit's sleep, the member's,
// in user@<uid>.service for the manager's (no_new_privs off, as an
// ordinary user service) or else in a system unit (no_new_privs on).
func confirmSleeper(pid int, u *user.User, unit string, inManager bool) bool {
	cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(cg)), "/"+unit+".service") || !ownedBy(pid, u.Uid) {
		return false
	}
	if inManager && !strings.Contains(string(cg), "/user@"+u.Uid+".service/") {
		return false
	}
	// the very file /bin/sleep is (merged /usr, multicall builds alike)
	exe, err1 := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	sleep, err2 := os.Stat("/bin/sleep")
	if err1 != nil || err2 != nil || !os.SameFile(exe, sleep) {
		return false
	}
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	want := "NoNewPrivs:\t1"
	if inManager {
		want = "NoNewPrivs:\t0"
	}
	return err == nil && strings.Contains(string(st), want)
}

// noSession is the subject for a process of the member's in no session.
// Judged by its own session if it has one; otherwise polkitd judges it as
// no session (allow_any) or, in some versions, by the member's display
// session (sd_uid_get_display): which one is read from its answers.
func noSession(t *testing.T, u *user.User, what string, pid int, cands []Kind) subject {
	sub := subject{
		name:  what,
		arg:   fmt.Sprintf("('unix-process', {'pid': <uint32 %d>, 'start-time': <uint64 %d>, 'uid': <int32 %s>})", pid, startTime(t, pid), u.Uid),
		kind:  NoSession,
		pid:   pid,
		start: startTime(t, pid),
		uid:   u.Uid,
	}
	if s := pidSession(pid); s != "" {
		sub.kind, sub.name = sessionKind(t, s), what+" (in session "+s+")"
		return sub
	}
	sub.candidates = cands
	if d := displaySession(u.Username); d != "" {
		sub.name = what + " (display session " + d + ")"
	}
	if len(sub.candidates) == 1 {
		sub.candidates = nil // no session to be judged by
	}
	return sub
}

// pidOnly logs once that busctl couldn't pass a pidfd.
var pidOnly sync.Once

// polkitVersion is polkitd's own, from the Authority's BackendVersion.
func polkitVersion(t *testing.T) int {
	out := run(t, "busctl", "get-property", "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
		"org.freedesktop.PolicyKit1.Authority", "BackendVersion")
	var v int
	if _, err := fmt.Sscanf(strings.TrimSpace(out), "s \"%d", &v); err != nil || v < 122 {
		t.Fatalf("polkit's version %q: not checked (122 is the floor)", strings.TrimSpace(out))
	}
	return v
}

// ask puts one CheckAuthorization to polkitd for a subject: on polkit
// 124 and later by a pidfd root opens (polkitd then trusts it, and gives
// rules subject.system_unit and no_new_privileges), else by pid and
// start time.
func ask(t *testing.T, version int, s *subject, id string) Answer {
	ans := Answer{Action: id, Kind: s.kind, Subject: s.name}
	var cmd *exec.Cmd
	parse := ParseCheckAuthorization
	if version >= 124 {
		fd, err := unix.PidfdOpen(s.pid, 0)
		if err != nil {
			ans.Err = "pidfd_open: " + err.Error()
			return ans
		}
		f := os.NewFile(uintptr(fd), "pidfd")
		defer f.Close()
		// the pidfd is for the process the subject was recorded as
		if st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", s.pid)); err != nil || startTimeOf(st) != s.start {
			ans.Err = "the subject's process has gone"
			return ans
		}
		cmd = exec.Command("busctl", "call", "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
			"org.freedesktop.PolicyKit1.Authority", "CheckAuthorization", "(sa{sv})sa{ss}us",
			"unix-process", "2", "pidfd", "h", "3", "uid", "i", s.uid, id, "0", "0", "")
		cmd.ExtraFiles = []*os.File{f} // fd 3
		parse = ParseBusctlCheck
	} else {
		cmd = exec.Command("gdbus", "call", "--system", "--dest", "org.freedesktop.PolicyKit1",
			"--object-path", "/org/freedesktop/PolicyKit1/Authority",
			"--method", "org.freedesktop.PolicyKit1.Authority.CheckAuthorization",
			s.arg, id, "{}", "0", "")
	}
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.CombinedOutput()
	if err != nil && version >= 124 && strings.Contains(string(out), "not supported as type") {
		// busctl before systemd 256 can't pass a file descriptor
		// (Ubuntu 24.04's 255): ask by pid, and say so.
		pidOnly.Do(func() {
			t.Log("busctl can't pass a pidfd here: every subject asked by pid and start time instead, so rules on system_unit and no_new_privileges go unexercised")
		})
		return ask(t, 0, s, id)
	}
	if err != nil {
		ans.Err = strings.TrimSpace(string(out))
	} else if ans.Authorized, ans.Challenge, ans.Temporary, err = parse(string(out)); err != nil {
		ans.Err = err.Error()
	}
	return ans
}

// groupsDiffer names a process of the member's whose held groups aren't
// exactly the group database's, or is empty. (A rule can grant on a
// group's absence, so fewer counts too.) The one exemption is the user
// manager's (sd-pam), which holds none.
func groupsDiffer(t *testing.T, u *user.User) string {
	want := dbGroups(t, u)
	// /proc mounted with hidepid hides other users' processes from a
	// checker outside the mount's gid= group: the scan would see nothing.
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Sprintf("/proc/self/mountinfo can't be read (%v)", err)
	}
	if hidden, gid := hidepid(string(mi)); hidden && !holdsGroup(gid) {
		return "/proc is mounted with hidepid and the checker isn't in its gid= group"
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Sprintf("/proc can't be listed (%v)", err)
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		// Only ENOENT or ESRCH means the process is gone; any other read
		// error is a process the checker can't see.
		st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("/proc/%d/status can't be read (%v)", pid, err)
		}
		if !statusUids(string(st), u.Uid) {
			continue
		}
		held := statusGroups(string(st))
		if held == want || (held == "" && sdPam(pid, u)) {
			continue
		}
		// Outside the first user namespace (a rootless container) fewer
		// groups are accepted; a group beyond the database's still
		// refuses (the lead's call, GC #16712).
		if !inFirstUserNS(pid) && subset(held, want) {
			continue
		}
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		return fmt.Sprintf("pid %d (%s) holds groups %q, the group database gives %q", pid, strings.TrimSpace(string(comm)), held, want)
	}
	return ""
}

// subgidOverlap names a group whose gid lies in one of the member's
// /etc/subgid ranges, or is empty. Each gid is looked up by key (getent
// group <gid> ...), since a network source such as sssd doesn't
// enumerate its groups.
func subgidOverlap(t *testing.T, u *user.User) string {
	b, err := os.ReadFile("/etc/subgid")
	if errors.Is(err, fs.ErrNotExist) {
		return "" // no ranges
	}
	if err != nil {
		return fmt.Sprintf("/etc/subgid can't be read (%v)", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(strings.TrimSpace(line), ":")
		if len(f) != 3 || (f[0] != u.Username && f[0] != u.Uid) {
			continue
		}
		start, err1 := strconv.ParseUint(f[1], 10, 32)
		n, err2 := strconv.ParseUint(f[2], 10, 32)
		if err1 != nil || err2 != nil {
			return "an /etc/subgid line it can't read: " + line
		}
		for lo := start; lo < start+n; lo += 4096 {
			args := []string{"group"}
			for g := lo; g < lo+4096 && g < start+n; g++ {
				args = append(args, strconv.FormatUint(g, 10))
			}
			// exit 0: every key found; 2: some not found, the usual case,
			// but also what a network source that can't be reached gives
			// (getent can't tell them apart). Anything else, or no getent,
			// is a lookup that didn't run.
			out, err := exec.Command("getent", args...).Output()
			var ee *exec.ExitError
			if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 2) {
				return fmt.Sprintf("the subgid lookup failed (%v)", err)
			}
			if g := strings.TrimSpace(string(out)); g != "" {
				return fmt.Sprintf("the member's subgid range %s:%s holds group %s", f[1], f[2], strings.SplitN(g, "\n", 2)[0])
			}
		}
	}
	return ""
}

// heldGroups are a process's supplementary groups, sorted, as one string.
func heldGroups(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "unreadable"
	}
	return statusGroups(string(b))
}

// holdsGroup: the checker's own process holds gid (its real or
// supplementary groups).
func holdsGroup(gid string) bool {
	if gid == "" {
		return false
	}
	if strconv.Itoa(os.Getgid()) == gid {
		return true
	}
	gs, _ := os.Getgroups()
	for _, g := range gs {
		if strconv.Itoa(g) == gid {
			return true
		}
	}
	return false
}

// dbGroups are the member's groups as the group database gives them
// (getgrouplist, through id), sorted, as one string.
func dbGroups(t *testing.T, u *user.User) string {
	return set(strings.Fields(run(t, "id", "-G", u.Username)))
}

// inFirstUserNS: the process is in the first user namespace, read
// from its uid_map and gid_map (world-readable, no ptrace access needed,
// unlike the ns/user link of another uid's process). It fails closed: a
// map it can't read counts as the first namespace, so the exact
// comparison applies.
func inFirstUserNS(pid int) bool {
	first, ok := initialUserNS(pid)
	return first || !ok
}

// initialUserNS: both of the process's id maps are the identity over
// every id, which only the first user namespace has unless a privileged
// process made one so (never the member); ok is false when a map can't
// be read.
func initialUserNS(pid int) (first, ok bool) {
	u, err1 := os.ReadFile(fmt.Sprintf("/proc/%d/uid_map", pid))
	g, err2 := os.ReadFile(fmt.Sprintf("/proc/%d/gid_map", pid))
	if err1 != nil || err2 != nil {
		return false, false
	}
	return identityMap(string(u)) && identityMap(string(g)), true
}

// sdPam: the process is (sd-pam), a child of the member's manager, in
// the first user namespace (a name and a parent can be had by any unit's
// process; dropping groups needs a namespace of one's own).
func sdPam(pid int, u *user.User) bool {
	if first, ok := initialUserNS(pid); !first || !ok {
		return false
	}
	comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if strings.TrimSpace(string(comm)) != "(sd-pam)" {
		return false
	}
	st, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	ppid := parentOf(st)
	out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", "user@"+u.Uid+".service").Output()
	return err == nil && ppid != 0 && strconv.Itoa(ppid) == strings.TrimSpace(string(out))
}

// conditions reads the facts the allowlist's conditional entries need.
func conditions(t *testing.T) Conditions {
	c := Conditions{FwupdOnlyTrusted: true, LocalSudoRules: true}
	// fwupd 2 reads fwupd.conf, then its mutable copy under /var/etc
	// (where fwupdmgr modify-config writes when /etc is read-only), earlier
	// ones daemon.conf; OnlyTrusted is on unless set off (any value but a
	// case-insensitive "true" is off here).
	for _, f := range []string{"/etc/fwupd/fwupd.conf", "/var/etc/fwupd/fwupd.conf", "/etc/fwupd/daemon.conf"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "OnlyTrusted" && !strings.EqualFold(strings.TrimSpace(v), "true") {
				c.FwupdOnlyTrusted = false
			}
		}
	}
	b, err := os.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		// sudo matches the database and its sources case-insensitively.
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "sudoers") {
			for _, src := range strings.Fields(strings.SplitN(v, "#", 2)[0]) {
				if !strings.EqualFold(src, "files") && !strings.HasPrefix(src, "[") {
					c.LocalSudoRules = false
				}
			}
		}
	}
	return c
}

func TestPolkitProbe(t *testing.T) {
	member := os.Getenv("VETTID_TEST_POLKIT_PROBE")
	if member == "" {
		t.Skip("a measurement for a VM: set VETTID_TEST_POLKIT_PROBE=<member> and run as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("run as root (it asks polkitd about another user's subjects)")
	}
	u, err := user.Lookup(member)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := ParsePkaction(run(t, "pkaction", "--verbose"))
	if err != nil {
		t.Fatal(err)
	}
	if first, ok := initialUserNS(os.Getpid()); !first || !ok {
		t.Fatal("the probe isn't in the first user namespace: groups would read unmapped")
	}
	version := polkitVersion(t)
	t.Logf("polkit %d: subjects asked by %s", version, map[bool]string{true: "pidfd", false: "pid and start time"}[version >= 124])
	conds := conditions(t)
	subs := subjects(t, u)
	var answers []Answer
	for i := range subs {
		s := &subs[i]
		var these []Answer
		for id := range actions {
			these = append(these, ask(t, version, s, id))
		}
		if len(s.candidates) > 1 {
			t.Logf("%s:", s.name)
			k, kept, excl, ok := KindFrom(actions, these, s.candidates)
			refusals := 0
			for _, a := range these {
				if a.Err == "" && !a.Authorized {
					refusals++
				}
			}
			for i, c := range kept {
				for j, o := range kept {
					if i != j {
						t.Logf("  %d of %d refusals explained by %s and not %s", excl[i][j], refusals, c, o)
					}
				}
			}
			if s.want != nil {
				// A session's kind, worked out from logind, needs only
				// to be consistent with its answers: no other kind
				// explains a refusal its kind doesn't (the want is the
				// first candidate, so it is kept[0]), and no other kind
				// is identified instead.
				ok = !ok || k == *s.want
				for i := 1; i < len(kept); i++ {
					if excl[i][0] != 0 {
						ok = false
					}
				}
				if !ok {
					t.Logf("  inconsistent with %s, worked out from logind", *s.want)
				}
				k = *s.want
			}
			if s.want == nil || ok {
				s.kind = k
			}
			if !ok {
				// Not checked: every answer of this subject's.
				t.Logf("  can't tell which kind polkitd judged it by")
				for j := range these {
					if these[j].Err == "" {
						these[j].Err = "the kind of subject polkitd judged it by is unknown"
					}
				}
			}
			for j := range these {
				these[j].Kind = s.kind
			}
		}
		// polkitd 124 and later judge a process subject by the group
		// database (getgrouplist), a caller on the bus by the groups its
		// process holds: where they differ, not checked.
		if held, want := heldGroups(s.pid), dbGroups(t, u); held != want {
			t.Logf("%s: holds groups %q, the group database gives %q: sign out and in again", s.name, held, want)
			for j := range these {
				if these[j].Err == "" {
					these[j].Err = "the process's groups differ from the group database"
				}
			}
		}
		answers = append(answers, these...)
	}
	// Every process of the member's, not only the subjects: one holding
	// groups the database doesn't give makes polkit not checked; so does
	// a subgid range of the member's that holds a real group.
	bad := groupsDiffer(t, u)
	if bad == "" {
		bad = subgidOverlap(t, u)
	}
	if bad != "" {
		t.Logf("%s: not checked for every subject", bad)
		for j := range answers {
			if answers[j].Err == "" {
				answers[j].Err = bad
			}
		}
	}
	t.Logf("%d actions; subjects:", len(actions))
	for _, s := range subs {
		t.Logf("  %s: %s", s.name, s.kind)
	}
	refused := 0
	t.Logf("conditions: %+v", conds)
	for _, a := range answers {
		for _, gate := range ExecPathIf {
			if a.Action == gate.action {
				t.Logf("gate %s for %s (%s): authorized %v, challenge %v, err %q", a.Action, a.Subject, a.Kind, a.Authorized, a.Challenge, a.Err)
			}
		}
	}
	t.Log("a passing run says nothing of a .policy file changed on disk: that is the package check's")
	for _, v := range Judge(actions, answers, conds) {
		if v.Result == Nothing {
			continue
		}
		t.Logf("%-11s %-62s %-22s %s", v.Result, v.Action, v.Kind, v.Reason)
		if v.Result == Refuse || v.Result == NotChecked {
			refused++
		}
	}
	if refused > 0 {
		t.Errorf("%d answers refuse %s or couldn't be checked", refused, member)
	}
}
