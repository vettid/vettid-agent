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
}

// sessionKind is a logind session's kind for polkit: active and local, or
// not. polkitd's logind backend calls a session local when it has a seat
// (sd_session_get_seat) and active when its state is active, so a
// seatless session, which logind marks active, is judged as inactive.
func sessionKind(t *testing.T, id string) Kind {
	props := map[string]string{}
	for _, line := range strings.Split(run(t, "loginctl", "show-session", id, "-p", "Seat", "-p", "State", "-p", "Remote"), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			props[k] = strings.TrimSpace(v)
		}
	}
	if props["Seat"] != "" && props["State"] == "active" && props["Remote"] == "no" {
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
			// polkit judges none by it; its processes are judged as the
			// no-session subject is.
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
	// A process of the member's in no session: a transient system service.
	unit := fmt.Sprintf("vettid-polkit-probe-%d", time.Now().UnixNano())
	run(t, "systemd-run", "--unit", unit, "--uid", u.Uid, "--gid", u.Gid, "--collect",
		"--property=NoNewPrivileges=yes", "--property=RuntimeMaxSec=600", "/bin/sleep", "600")
	t.Cleanup(func() { _ = exec.Command("systemctl", "stop", unit).Run() })
	var pid int
	for i := 0; i < 50 && pid == 0; i++ {
		pid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(run(t, "systemctl", "show", "-p", "MainPID", unit), "MainPID=")))
		if pid == 0 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if pid == 0 {
		t.Fatal("the no-session process didn't start")
	}
	// Judged as polkit judges it: its own session, else the member's
	// display session, else none.
	kind, how := NoSession, "no session"
	if s := pidSession(pid); s != "" {
		kind, how = sessionKind(t, s), "its session "+s
	} else if d := displaySession(u.Username); d != "" {
		kind, how = sessionKind(t, d), "the display session "+d
	}
	out = append(out, subject{
		name: "no-session process (judged by " + how + ")",
		arg:  fmt.Sprintf("('unix-process', {'pid': <uint32 %d>, 'start-time': <uint64 %d>, 'uid': <int32 %s>})", pid, startTime(t, pid), u.Uid),
		kind: kind,
	})
	return out
}

// conditions reads the facts the allowlist's conditional entries need.
func conditions(t *testing.T) Conditions {
	c := Conditions{FwupdOnlyTrusted: true, LocalSudoRules: true}
	// fwupd 2 reads fwupd.conf, earlier ones daemon.conf; OnlyTrusted is
	// on unless set off.
	for _, f := range []string{"/etc/fwupd/fwupd.conf", "/etc/fwupd/daemon.conf"} {
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
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "sudoers" {
			for _, src := range strings.Fields(strings.SplitN(v, "#", 2)[0]) {
				if src != "files" {
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
	for _, s := range subs {
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
			answers = append(answers, ans)
		}
	}
	t.Logf("%d actions; subjects:", len(actions))
	for _, s := range subs {
		t.Logf("  %s: %s", s.name, s.kind)
	}
	refused := 0
	t.Logf("conditions: %+v", conds)
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
