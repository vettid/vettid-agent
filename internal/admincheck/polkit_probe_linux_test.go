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

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(st), "\n") {
		if ids := strings.Fields(strings.TrimPrefix(line, "Uid:")); strings.HasPrefix(line, "Uid:") {
			return len(ids) == 4 && ids[0] == uid && ids[1] == uid && ids[2] == uid && ids[3] == uid
		}
	}
	return false
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
	for _, line := range strings.Split(run(t, "loginctl", "list-sessions", "--no-legend"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == u.Uid {
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
			out = append(out, subject{
				name: fmt.Sprintf("session %s (pid %d)", f[0], pid),
				arg:  fmt.Sprintf("('unix-process', {'pid': <uint32 %d>, 'start-time': <uint64 %d>, 'uid': <int32 %s>})", pid, startTime(t, pid), u.Uid),
				kind: sessionKind(t, f[0]),
			})
		}
	}
	// Processes of the member's in no session: a transient system service,
	// and a unit of the member's own service manager if it runs.
	if pid := sleeper(t, nil, "systemd-run", "--uid", u.Uid, "--gid", u.Gid); pid != 0 {
		out = append(out, noSession(t, u, "system service", pid))
	} else {
		t.Fatal("the no-session process didn't start")
	}
	if exec.Command("systemctl", "is-active", "--quiet", "user@"+u.Uid+".service").Run() == nil {
		m := u.Username + "@"
		if pid := sleeper(t, []string{"--user", "--machine=" + m}, "systemd-run", "--user", "--machine="+m); pid != 0 {
			out = append(out, noSession(t, u, "user service", pid))
		} else {
			t.Error("the user service didn't start: not checked")
		}
	} else {
		t.Logf("%s's service manager isn't running: no user service asked", u.Username)
	}
	return out
}

// sleeper starts a transient unit that sleeps, with the given systemd-run
// command (and systemctl scope), and returns its main pid, or 0 if it
// didn't start.
func sleeper(t *testing.T, scope []string, cmd ...string) int {
	unit := fmt.Sprintf("vettid-polkit-probe-%d", time.Now().UnixNano())
	args := append(append([]string{}, cmd[1:]...), "--unit", unit, "--collect",
		"--property=NoNewPrivileges=yes", "--property=RuntimeMaxSec=600", "/bin/sleep", "600")
	if out, err := exec.Command(cmd[0], args...).CombinedOutput(); err != nil {
		t.Logf("%s: %v\n%s", strings.Join(cmd, " "), err, out)
		return 0
	}
	ctl := append(append([]string{}, scope...), "stop", unit)
	t.Cleanup(func() { _ = exec.Command("systemctl", ctl...).Run() })
	show := append(append([]string{}, scope...), "show", "-p", "MainPID", "--value", unit)
	for i := 0; i < 50; i++ {
		out, _ := exec.Command("systemctl", show...).Output()
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(out))); pid != 0 {
			return pid
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0
}

// noSession is the subject for a process of the member's in no session.
// Judged by its own session if it has one; otherwise polkitd judges it as
// no session (allow_any) or, in some versions, by the member's display
// session (sd_uid_get_display): which one is read from its answers.
func noSession(t *testing.T, u *user.User, what string, pid int) subject {
	sub := subject{
		name: what,
		arg:  fmt.Sprintf("('unix-process', {'pid': <uint32 %d>, 'start-time': <uint64 %d>, 'uid': <int32 %s>})", pid, startTime(t, pid), u.Uid),
		kind: NoSession,
	}
	if s := pidSession(pid); s != "" {
		sub.kind, sub.name = sessionKind(t, s), what+" (in session "+s+")"
		return sub
	}
	// Candidates: none, and the kind of each of the member's sessions
	// (the display session's among them).
	sub.candidates = []Kind{NoSession}
	for _, id := range memberSessions(t, u) {
		if exec.Command("loginctl", "show-session", id).Run() != nil {
			continue // closed since the listing
		}
		k := sessionKind(t, id)
		dup := false
		for _, c := range sub.candidates {
			dup = dup || c == k
		}
		if !dup {
			sub.candidates = append(sub.candidates, k)
		}
	}
	if d := displaySession(u.Username); d != "" {
		sub.name = what + " (display session " + d + ")"
	}
	if len(sub.candidates) == 1 {
		sub.candidates = nil // no session to be judged by
	}
	return sub
}

// memberSessions are the member's logind sessions.
func memberSessions(t *testing.T, u *user.User) []string {
	var ids []string
	for _, line := range strings.Split(run(t, "loginctl", "list-sessions", "--no-legend"), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[1] == u.Uid {
			ids = append(ids, f[0])
		}
	}
	return ids
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
	conds := conditions(t)
	subs := subjects(t, u)
	var answers []Answer
	for i := range subs {
		s := &subs[i]
		var these []Answer
		for id := range actions {
			ans := Answer{Action: id, Kind: s.kind, Subject: s.name}
			cmd := exec.Command("gdbus", "call", "--system", "--dest", "org.freedesktop.PolicyKit1",
				"--object-path", "/org/freedesktop/PolicyKit1/Authority",
				"--method", "org.freedesktop.PolicyKit1.Authority.CheckAuthorization",
				s.arg, id, "{}", "0", "")
			cmd.Env = append(os.Environ(), "LC_ALL=C")
			out, err := cmd.CombinedOutput()
			if err != nil {
				ans.Err = strings.TrimSpace(string(out))
			} else if ans.Authorized, ans.Challenge, ans.Temporary, err = ParseCheckAuthorization(string(out)); err != nil {
				ans.Err = err.Error()
			}
			these = append(these, ans)
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
			s.kind = k
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
		answers = append(answers, these...)
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
