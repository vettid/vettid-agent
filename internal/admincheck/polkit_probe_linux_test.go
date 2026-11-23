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
// not.
func sessionKind(t *testing.T, id string) Kind {
	props := run(t, "loginctl", "show-session", id, "-p", "Active", "-p", "Remote")
	if strings.Contains(props, "Active=yes") && strings.Contains(props, "Remote=no") {
		return Active
	}
	return Inactive
}

// pidSession is the logind session a process belongs to, as logind says
// (sd_pid_get_session, through ps): a session scope's, or a manager-class
// session's for the user's service manager.
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
// below it: a session scope, or for a manager-class session, the user's
// service manager.
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
			// Asked by a process of the member's in the session, which
			// polkit judges by that session: polkitd 124 on Ubuntu 24.04
			// aborts on a unix-session subject. (Not the leader: a tty
			// session's leader is login, running as root.)
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
	run(t, "systemd-run", "--unit", unit, "--uid", u.Uid, "--gid", u.Gid, "--property=NoNewPrivileges=yes", "/bin/sleep", "600")
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
	for _, v := range Judge(actions, answers) {
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
