package admincheck

import (
	"strings"
	"testing"
)

const pkactionSample = `org.freedesktop.udisks2.filesystem-mount:
  description:       Mount a filesystem
  message:           Authentication is required to mount the filesystem
  vendor:            The Udisks Project
  vendor_url:        https://github.com/storaged-project/udisks
  icon:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   yes

org.freedesktop.systemd1.manage-units:
  description:       Manage system services or other units
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin_keep

org.gnome.settings-daemon.plugins.power.backlight-helper:
  description:       Modify the laptop brightness
  implicit any:      no
  implicit inactive: no
  implicit active:   yes
  annotation:        org.freedesktop.policykit.exec.path -> /usr/libexec/gsd-backlight-helper

org.example.helper:
  description:       Run a helper
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   yes
  annotation:        org.freedesktop.policykit.exec.path -> /usr/bin/example-helper

org.freedesktop.timedate1.set-time:
  implicit any:      auth_admin_keep
  implicit inactive: auth_admin_keep
  implicit active:   auth_admin_keep

org.example.admin:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin

org.freedesktop.sysupdate1.check:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   yes

org.freedesktop.login1.power-off:
  implicit any:      auth_admin_keep
  implicit inactive: auth_admin_keep
  implicit active:   yes
  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.login1.set-wall-message

org.freedesktop.login1.power-off-ignore-inhibit:
  implicit any:      auth_admin_keep
  implicit inactive: auth_admin_keep
  implicit active:   auth_admin_keep
  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.login1.power-off

org.freedesktop.login1.set-wall-message:
  implicit any:      auth_admin_keep
  implicit inactive: auth_admin_keep
  implicit active:   auth_admin_keep

org.gtk.vfs.file-operations-helper:
  implicit any:      no
  implicit inactive: no
  implicit active:   auth_admin_keep
  annotation:        org.freedesktop.policykit.exec.path -> /usr/libexec/gvfsd-admin

org.gtk.vfs.file-operations:
  implicit any:      no
  implicit inactive: no
  implicit active:   auth_admin_keep

com.ubuntu.update-notifier.pkexec.package-system-locked:
  implicit any:      no
  implicit inactive: yes
  implicit active:   yes
  annotation:        org.freedesktop.policykit.exec.path -> /usr/lib/update-notifier/package-system-locked

org.example.self-implier:
  implicit any:      auth_self
  implicit inactive: auth_self
  implicit active:   auth_self
  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.login1.set-wall-message

org.example.no-implier:
  implicit any:      no
  implicit inactive: no
  implicit active:   no
  annotation:        org.freedesktop.policykit.imply -> org.freedesktop.login1.set-wall-message

org.example.chain-a:
  implicit any:      no
  implicit inactive: no
  implicit active:   yes
  annotation:        org.freedesktop.policykit.imply -> org.example.chain-b org.example.other

org.example.chain-b:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin
  annotation:        org.freedesktop.policykit.imply -> org.example.chain-c

org.example.chain-c:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin

org.gnome.software.dkms-test:
  implicit any:      yes
  implicit inactive: yes
  implicit active:   yes
  annotation:        org.freedesktop.policykit.exec.path -> /usr/libexec/gnome-software-dkms-helper
  annotation:        org.freedesktop.policykit.exec.argv1 -> --test-dkms

org.gnome.software.akmods-test:
  implicit any:      yes
  implicit inactive: yes
  implicit active:   yes
  annotation:        org.freedesktop.policykit.exec.path -> /usr/libexec/another-helper
  annotation:        org.freedesktop.policykit.exec.argv1 -> --test-akmods

org.freedesktop.import1.pull-tar:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   yes

org.freedesktop.fwupd.update-internal:
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   auth_admin_keep

org.freedesktop.hostname1.set-hostname:
  implicit any:      auth_admin_keep
  implicit inactive: auth_admin_keep
  implicit active:   auth_admin_keep
`

func TestParsePkaction(t *testing.T) {
	a, err := ParsePkaction(pkactionSample)
	if err != nil {
		t.Fatal(err)
	}
	m := a["org.freedesktop.udisks2.filesystem-mount"]
	if m.Any != AuthAdmin || m.Inactive != AuthAdmin || m.Active != Yes || m.ExecPath != "" {
		t.Errorf("mount: %+v", m)
	}
	if got := a["org.example.helper"].ExecPath; got != "/usr/bin/example-helper" {
		t.Errorf("exec.path: %q", got)
	}
	if len(a) != 23 {
		t.Errorf("%d actions, want 23", len(a))
	}
	if got := a["org.example.chain-a"].Implies; len(got) != 2 || got[0] != "org.example.chain-b" || got[1] != "org.example.other" {
		t.Errorf("two implied: %q", got)
	}
	if got := a["org.freedesktop.login1.power-off"].Implies; len(got) != 1 || got[0] != "org.freedesktop.login1.set-wall-message" {
		t.Errorf("imply: %q", got)
	}
	if _, err := ParsePkaction("org.x:\n  implicit active:   sometimes\n"); err == nil {
		t.Error("an unknown default: no error")
	}
}

func TestParseCheckAuthorization(t *testing.T) {
	if _, _, _, err := ParseCheckAuthorization("Error: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed"); err == nil {
		t.Error("an error answer: no error")
	}
	for _, c := range []struct {
		out              string
		auth, chal, temp bool
	}{
		{"((true, false, @a{ss} {}),)", true, false, false}, // gdbus's empty-dict form
		{"((true, false, {}),)", true, false, false},
		{"((false, false, @a{ss} {}),)", false, false, false},
		{"((false, true, {}),)", false, true, false},
		{"((true, false, {'polkit.temporary_authorization_id': 'tmpauthz1'}),)", true, false, true},
	} {
		auth, chal, temp, err := ParseCheckAuthorization(c.out)
		if err != nil || auth != c.auth || chal != c.chal || temp != c.temp {
			t.Errorf("%q: %v %v %v %v", c.out, auth, chal, temp, err)
		}
	}
}

var met = Conditions{FwupdOnlyTrusted: true, LocalSudoRules: true}

func TestJudge(t *testing.T) {
	actions, err := ParsePkaction(pkactionSample)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Result{}
	var answers []Answer
	add := func(id string, k Kind, auth bool, r Result) {
		answers = append(answers, Answer{Action: id, Kind: k, Authorized: auth})
		want[id+"/"+k.String()] = r
	}
	add("org.freedesktop.udisks2.filesystem-mount", Active, true, Nothing)                 // yes for an active session
	add("org.freedesktop.udisks2.filesystem-mount", NoSession, true, Refuse)               // auth_admin for none
	add("org.freedesktop.systemd1.manage-units", Active, true, Refuse)                     // always refuses
	add("org.freedesktop.systemd1.manage-units", Inactive, false, Nothing)                 // not granted
	add("org.gnome.settings-daemon.plugins.power.backlight-helper", Active, true, Nothing) // allowed helper
	add("org.example.helper", Active, true, Refuse)                                        // another exec.path
	add("org.freedesktop.timedate1.set-time", Active, true, Report)                        // allowlisted
	add("org.example.admin", Active, true, Refuse)                                         // an unknown admin action
	add("org.freedesktop.sysupdate1.check", Active, true, Report)                          // recorded yes
	add("org.unknown", Active, true, NotChecked)                                           // not listed
	answers = append(answers, Answer{Action: "org.example.admin", Kind: Inactive, Err: "timeout"})
	want["org.example.admin/inactive"] = NotChecked
	answers = append(answers, Answer{Action: "org.freedesktop.timedate1.set-time", Kind: Inactive, Authorized: true, Temporary: true})
	want["org.freedesktop.timedate1.set-time/inactive"] = Report
	add("com.ubuntu.update-notifier.pkexec.package-system-locked", Active, true, Nothing) // a fixed helper
	add("org.freedesktop.sysupdate1.check", NoSession, true, Refuse)                      // recorded yes for active only
	add("org.freedesktop.sysupdate1.check", Inactive, true, Refuse)
	add("org.gnome.software.dkms-test", Active, true, Nothing)         // allowed by id, with its own helper
	add("org.gnome.software.akmods-test", Active, true, Refuse)        // allowed by id, but another helper
	add("org.freedesktop.import1.pull-tar", Active, true, Refuse)      // a prefix, though yes for active
	add("org.freedesktop.fwupd.update-internal", Active, true, Report) // its condition met
	add("org.freedesktop.hostname1.set-hostname", Active, true, Report)
	for _, id := range []string{"org.rpm.dnf.v0.rpm.execute_transaction", "org.rpm.dnf.v0.rpm.Repo.conf_write", "org.rpm.dnf.v0.base.Config.override"} {
		actions[id] = Action{ID: id, Any: Yes, Inactive: Yes, Active: Yes}
		add(id, Active, true, Refuse) // always refuses, whatever its defaults
	}
	actions["org.freedesktop.machine1.register-machine"] = Action{ID: "org.freedesktop.machine1.register-machine", Any: AuthAdmin, Inactive: AuthAdmin, Active: Yes}
	add("org.freedesktop.machine1.register-machine", Active, true, Report)
	add("org.freedesktop.machine1.register-machine", Inactive, true, Refuse)
	for _, v := range Judge(actions, answers, met) {
		if w := want[v.Action+"/"+v.Kind.String()]; v.Result != w {
			t.Errorf("%s (%s): %s (%s), want %s", v.Action, v.Kind, v.Result, v.Reason, w)
		}
	}
}

// Grants that follow from another answer for the same subject.
func TestJudgeLifts(t *testing.T) {
	actions, err := ParsePkaction(pkactionSample)
	if err != nil {
		t.Fatal(err)
	}
	const (
		wall   = "org.freedesktop.login1.set-wall-message"
		off    = "org.freedesktop.login1.power-off"
		offII  = "org.freedesktop.login1.power-off-ignore-inhibit"
		helper = "org.gtk.vfs.file-operations-helper"
		ops    = "org.gtk.vfs.file-operations"
	)
	ans := func(subject, id string, k Kind, auth, chal bool) Answer {
		return Answer{Action: id, Kind: k, Subject: subject, Authorized: auth, Challenge: chal}
	}
	result := func(vs []Verdict, subject, id string) Result {
		for _, v := range vs {
			if v.Subject == subject && v.Action == id {
				return v.Result
			}
		}
		return ""
	}
	for _, c := range []struct {
		name    string
		answers []Answer
		id      string
		want    Result
	}{
		{"implied by a grant its default allows", []Answer{ans("s", off, Active, true, false), ans("s", wall, Active, true, false)}, wall, Report},
		{"implied by a refused grant", []Answer{ans("s", offII, Active, true, false), ans("s", wall, Active, true, false)}, wall, Refuse},
		{"the implying grant asked of another subject", []Answer{ans("t", off, Active, true, false), ans("s", wall, Active, true, false)}, wall, Refuse},
		{"the implying action not granted", []Answer{ans("s", off, Active, false, true), ans("s", wall, Active, true, false)}, wall, Refuse},
		{"the helper while operations challenge", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, false, true)}, helper, Report},
		{"the helper while operations are granted", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, true, false)}, helper, Refuse},
		{"the helper while operations are refused outright", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, false, false)}, helper, Refuse},
		{"the helper with operations unasked", []Answer{ans("s", helper, Active, true, false)}, helper, Refuse},
		{"the helper with operations an error", []Answer{ans("s", helper, Active, true, false), {Action: ops, Kind: Active, Subject: "s", Err: "timeout"}}, helper, Refuse},
		{"the helper while operations are granted to another subject", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, false, true), ans("t", ops, NoSession, true, false)}, helper, Refuse},
		{"the helper while operations are refused outright to another subject", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, false, true), ans("t", ops, NoSession, false, false)}, helper, Report},
		{"the helper while another subject's operations ask for its own password", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, false, true), ans("t", ops, NoSession, false, true)}, helper, Refuse},
		{"the helper while another subject's operations error", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, false, true), {Action: ops, Kind: Active, Subject: "t", Err: "timeout"}}, helper, Refuse},
		{"the helper while operations challenge every subject", []Answer{ans("s", helper, Active, true, false), ans("s", ops, Active, false, true), ans("t", ops, Active, false, true)}, helper, Report},
		{"implied by a grant whose default is auth_self", []Answer{ans("s", "org.example.self-implier", Active, true, false), ans("s", wall, Active, true, false)}, wall, Refuse},
		{"implied by a grant whose default is no", []Answer{ans("s", "org.example.no-implier", Active, true, false), ans("s", wall, Active, true, false)}, wall, Refuse},
		{"one level: the implied grant implies nothing", []Answer{ans("s", "org.example.chain-a", Active, true, false), ans("s", "org.example.chain-b", Active, true, false), ans("s", "org.example.chain-c", Active, true, false)}, "org.example.chain-c", Refuse},
		{"one level: the first is lifted", []Answer{ans("s", "org.example.chain-a", Active, true, false), ans("s", "org.example.chain-b", Active, true, false), ans("s", "org.example.chain-c", Active, true, false)}, "org.example.chain-b", Report},
	} {
		if got := result(Judge(actions, c.answers, met), "s", c.id); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// The allowlist's conditional entries refuse when their condition isn't met.
func TestJudgeConditions(t *testing.T) {
	actions, err := ParsePkaction(pkactionSample)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id    string
		conds Conditions
		want  Result
	}{
		{"org.freedesktop.fwupd.update-internal", Conditions{LocalSudoRules: true}, Refuse},
		{"org.freedesktop.fwupd.update-internal", met, Report},
		{"org.freedesktop.hostname1.set-hostname", Conditions{FwupdOnlyTrusted: true}, Refuse},
		{"org.freedesktop.hostname1.set-hostname", met, Report},
		{"org.freedesktop.hostname1.set-hostname", Conditions{}, Refuse},
	} {
		vs := Judge(actions, []Answer{{Action: c.id, Kind: Active, Authorized: true}}, c.conds)
		if vs[0].Result != c.want {
			t.Errorf("%s with %+v: %s (%s), want %s", c.id, c.conds, vs[0].Result, vs[0].Reason, c.want)
		}
	}
	for id := range conditional {
		if _, ok := Allowlist[id]; !ok {
			t.Errorf("%s: conditional, but not allowlisted", id)
		}
	}
}

// §11.4: the allowlist is named here entry by entry, so a change to it is
// a change to this test too.
func TestAllowlistNamed(t *testing.T) {
	want := []string{
		"com.canonical.controlcenter.datetime.configure",
		"com.endlessm.ParentalControls.AppFilter.ReadAny",
		"com.endlessm.ParentalControls.SessionLimits.ReadAny",
		"com.ubuntu.whoopsiepreferences.change",
		"org.debian.apt.upgrade-packages",
		"org.fedoraproject.FirewallD1.config.info",
		"org.fedoraproject.FirewallD1.direct.info",
		"org.fedoraproject.FirewallD1.info",
		"org.fedoraproject.FirewallD1.policies.info",
		"org.fedoraproject.thirdparty.opt-out",
		"org.freedesktop.bolt.authorize",
		"org.freedesktop.bolt.enroll",
		"org.freedesktop.bolt.manage",
		"org.freedesktop.Flatpak.app-install",
		"org.freedesktop.Flatpak.app-uninstall",
		"org.freedesktop.Flatpak.runtime-install",
		"org.freedesktop.Flatpak.runtime-uninstall",
		"org.freedesktop.fwupd.update-internal",
		"org.freedesktop.hostname1.set-hostname",
		"org.freedesktop.hostname1.set-static-hostname",
		"org.freedesktop.locale1.set-keyboard",
		"org.freedesktop.locale1.set-locale",
		"org.freedesktop.login1.handle-hibernate-key",
		"org.freedesktop.login1.hibernate-multiple-sessions",
		"org.freedesktop.login1.hibernate",
		"org.freedesktop.Malcontent.WebFilter.ReadAny",
		"org.freedesktop.NetworkManager.settings.modify.system",
		"org.freedesktop.packagekit.system-update",
		"org.freedesktop.packagekit.trigger-offline-update",
		"org.freedesktop.packagekit.trigger-offline-upgrade",
		"org.freedesktop.packagekit.upgrade-system",
		"org.freedesktop.timedate1.set-local-rtc",
		"org.freedesktop.timedate1.set-ntp",
		"org.freedesktop.timedate1.set-time",
		"org.freedesktop.timedate1.set-timezone",
		"org.freedesktop.udisks2.encrypted-unlock-system",
		"org.freedesktop.udisks2.filesystem-fstab",
		"org.freedesktop.udisks2.filesystem-mount-system",
		"org.freedesktop.upower.hibernate",
		"org.gnome.controlcenter.datetime.configure",
		"org.gnome.controlcenter.set-keyboard",
		"org.gnome.cpufreqselector",
		"org.kde.kcontrol.kcmclock.save",
		"org.mate.cpufreqselector",
		"org.mate.settingsdaemon.datetimemechanism.settime",
		"org.opensuse.cupspkhelper.mechanism.class-edit",
		"org.opensuse.cupspkhelper.mechanism.devices-get",
		"org.opensuse.cupspkhelper.mechanism.job-edit",
		"org.opensuse.cupspkhelper.mechanism.job-not-owned-edit",
		"org.opensuse.cupspkhelper.mechanism.printer-enable",
		"org.opensuse.cupspkhelper.mechanism.printer-set-default",
	}
	if len(want) != len(Allowlist) {
		t.Errorf("%d allowlisted, want %d", len(Allowlist), len(want))
	}
	for _, id := range want {
		if Allowlist[id] == "" {
			t.Errorf("%s: not allowlisted, or with no reason", id)
		}
		if _, ok := alwaysRefuses(Action{ID: id}); ok {
			t.Errorf("%s: allowlisted and always refused", id)
		}
	}
	for id, why := range AlwaysRefuse {
		if why == "" {
			t.Errorf("%s: always refused with no reason", id)
		}
	}
	for path, why := range ExecPathAllow {
		if why == "" || !strings.HasPrefix(path, "/") {
			t.Errorf("%s: %q", path, why)
		}
	}
	for id, kinds := range RecordedYes {
		if _, ok := alwaysRefuses(Action{ID: id}); !ok || len(kinds) == 0 {
			t.Errorf("%s: recorded yes, but not always refused or for no kind", id)
		}
	}
}

// KindFrom reads the kind from refusals only, and refuses mixed evidence.
func TestKindFrom(t *testing.T) {
	ans := func(id string, auth, chal bool) Answer { return Answer{Action: id, Authorized: auth, Challenge: chal} }
	actions := map[string]Action{
		// any auth_admin, active yes: a challenge says any
		"ch": {Any: AuthAdmin, Inactive: AuthAdmin, Active: Yes},
		// any no, active auth_admin_keep: a challenge says active
		"ak": {Any: No, Inactive: No, Active: AuthAdminKeep},
		// the same for every kind: no signal
		"same": {Any: AuthAdmin, Inactive: AuthAdmin, Active: AuthAdmin},
		// auth_self against auth_admin: both explain a challenge
		"self": {Any: AuthSelf, Inactive: AuthSelf, Active: AuthAdmin},
		// any no, active yes
		"ny": {Any: No, Inactive: No, Active: Yes},
		// any no, inactive no, active auth_admin: for three candidates
		"ak3": {Any: No, Inactive: No, Active: AuthAdminKeep},
		// any and inactive the same
		"ai": {Any: AuthAdmin, Inactive: AuthAdmin, Active: Yes},
		// recorded yes for active only, the same defaults for every kind
		"org.freedesktop.sysupdate1.check": {Any: AuthAdmin, Inactive: AuthAdmin, Active: AuthAdmin},
	}
	many := func(id string, n int, auth, chal bool) []Answer {
		var out []Answer
		for i := 0; i < n; i++ {
			out = append(out, ans(id, auth, chal))
		}
		return out
	}
	errs := func(id string, n int) []Answer {
		var out []Answer
		for i := 0; i < n; i++ {
			out = append(out, Answer{Action: id, Err: "timeout"})
		}
		return out
	}
	both := []Kind{NoSession, Active}
	for _, c := range []struct {
		name    string
		answers []Answer
		cands   []Kind
		want    Kind
		ok      bool
	}{
		{"any, with 50 grants that are yes for active", append(many("ch", 6, false, true), append(many("ch", 50, true, false), ans("same", false, true), ans("self", false, true))...), both, NoSession, true},
		{"active", many("ak", 6, false, true), both, Active, true},
		{"any, from outright refusals", many("ny", 5, false, false), both, NoSession, true},
		{"too little signal", many("ny", 4, false, false), both, NoSession, false},
		{"mixed: a rule asks where any's default refuses", append(many("ch", 6, false, true), many("ak", 1, false, true)...), both, NoSession, false},
		{"everything distinguishing granted", append(many("ch", 6, true, false), ans("same", false, true)), both, NoSession, false},
		{"errors count for nothing", append(many("ak", 6, false, true), errs("ny", 6)...), both, Active, true},
		{"errors alone say nothing", errs("ny", 6), both, NoSession, false},
		{"grants count for nothing", append(many("ak", 6, false, true), many("ny", 6, true, false)...), both, Active, true},
		{"unknown actions count for nothing", append(many("ny", 4, false, false), many("zz", 6, false, false)...), both, NoSession, false},
		{"three candidates", many("ak3", 6, false, true), []Kind{NoSession, Inactive, Active}, Active, true},
		{"candidates whose defaults agree are one", many("ai", 2, false, true), []Kind{NoSession, Inactive}, NoSession, true},
		{"not one where a recorded yes differs", append(many("same", 2, false, true), ans("org.freedesktop.sysupdate1.check", true, false)), []Kind{Active, Inactive}, NoSession, false},
		{"no candidates", many("ak", 6, false, true), nil, NoSession, false},
		{"one candidate", many("ak", 6, false, true), []Kind{Active}, NoSession, false},
	} {
		k, _, excl, ok := KindFrom(actions, c.answers, c.cands)
		if k != c.want || ok != c.ok {
			t.Errorf("%s: %s %v, want %s %v (%v)", c.name, k, ok, c.want, c.ok, excl)
		}
	}
}

// Rules this branch added after the measurements: a grant over a default
// of no refuses (and lifts like an administrator's); the key tests are
// pinned to their mode; imply is split on single spaces.
func TestJudgeNoDefaultAndArgv1(t *testing.T) {
	actions := map[string]Action{
		"org.x.no":      {ID: "org.x.no", Any: No, Inactive: No, Active: Yes},
		"org.x.implier": {ID: "org.x.implier", Any: No, Inactive: No, Active: Yes, Implies: []string{"org.x.no"}},
		"org.gnome.software.dkms-test": {ID: "org.gnome.software.dkms-test", Any: Yes, Inactive: Yes, Active: Yes,
			ExecPath: "/usr/libexec/gnome-software-dkms-helper", ExecArgv1: "--enroll-dkms"},
	}
	one := func(as ...Answer) map[string]Result {
		out := map[string]Result{}
		for _, v := range Judge(actions, as, met) {
			out[v.Action+"/"+v.Kind.String()] = v.Result
		}
		return out
	}
	got := one(Answer{Action: "org.x.no", Kind: Inactive, Authorized: true, Subject: "s"})
	if got["org.x.no/inactive"] != Refuse {
		t.Errorf("a grant over no: %v", got)
	}
	got = one(Answer{Action: "org.x.no", Kind: Active, Authorized: true, Subject: "s"})
	if got["org.x.no/active"] != Nothing {
		t.Errorf("yes for active: %v", got)
	}
	got = one(Answer{Action: "org.x.implier", Kind: Active, Authorized: true, Subject: "s"},
		Answer{Action: "org.x.no", Kind: Active, Authorized: true, Subject: "s"})
	if got["org.x.no/active"] != Nothing {
		t.Errorf("implied, yes anyway: %v", got)
	}
	actions["org.x.yes-inactive"] = Action{ID: "org.x.yes-inactive", Any: No, Inactive: Yes, Active: Yes, Implies: []string{"org.x.no"}}
	got = one(Answer{Action: "org.x.yes-inactive", Kind: Inactive, Authorized: true, Subject: "s"},
		Answer{Action: "org.x.no", Kind: Inactive, Authorized: true, Subject: "s"})
	if got["org.x.no/inactive"] != Report {
		t.Errorf("a grant over no, implied by an accepted grant: %v", got)
	}
	got = one(Answer{Action: "org.gnome.software.dkms-test", Kind: Active, Authorized: true, Subject: "s"})
	if got["org.gnome.software.dkms-test/active"] != Refuse {
		t.Errorf("the key test's id in another mode: %v", got)
	}
	a, err := ParsePkaction("org.x:\n  implicit any:      no\n  implicit inactive: no\n  implicit active:   no\n  annotation:        org.freedesktop.policykit.imply -> a\tb  c\n")
	if err != nil || len(a["org.x"].Implies) != 2 || a["org.x"].Implies[0] != "a\tb" || a["org.x"].Implies[1] != "c" {
		t.Errorf("imply split: %q %v", a["org.x"].Implies, err)
	}
}

// Candidates whose defaults differ only by a keep are one.
func TestKindFromKeepMerge(t *testing.T) {
	for _, pair := range [][2]Default{{AuthAdmin, AuthAdminKeep}, {AuthSelf, AuthSelfKeep}} {
		actions := map[string]Action{"k": {ID: "k", Any: pair[0], Inactive: pair[0], Active: pair[1]}}
		k, _, _, ok := KindFrom(actions, []Answer{{Action: "k", Challenge: true}}, []Kind{Active, Inactive})
		if !ok || k != Active {
			t.Errorf("%s against %s: %s %v", pair[0], pair[1], k, ok)
		}
	}
}

// The gvfs gate lifts only its own action id, not another action that
// runs the same program.
func TestGateByID(t *testing.T) {
	actions := map[string]Action{
		"org.x.other":                 {ID: "org.x.other", Any: No, Inactive: No, Active: AuthAdminKeep, ExecPath: "/usr/libexec/gvfsd-admin"},
		"org.gtk.vfs.file-operations": {ID: "org.gtk.vfs.file-operations", Any: No, Inactive: No, Active: AuthAdminKeep},
	}
	vs := Judge(actions, []Answer{
		{Action: "org.x.other", Kind: Active, Subject: "s", Authorized: true},
		{Action: "org.gtk.vfs.file-operations", Kind: Active, Subject: "s", Challenge: true},
	}, met)
	for _, v := range vs {
		if v.Action == "org.x.other" && v.Result != Refuse {
			t.Errorf("another id running gvfsd-admin: %s (%s)", v.Result, v.Reason)
		}
	}
}

func TestParseBusctlCheck(t *testing.T) {
	for _, c := range []struct {
		out              string
		auth, chal, temp bool
		bad              bool
	}{
		{out: "(bba{ss}) true false 0", auth: true},
		{out: "(bba{ss}) false true 1 \"polkit.result\" \"auth_self\"", chal: true},
		{out: "(bba{ss}) true false 1 \"polkit.temporary_authorization_id\" \"tmpauthz3\"", auth: true, temp: true},
		{out: "(bba{ss}) true false 1 \"a \\\"b\\\"\" \"c d\"", auth: true},
		{out: "(bba{ss}) true false 2 \"a\" \"b\"", bad: true},
		{out: "(bb) true false", bad: true},
		{out: "(bba{ss}) maybe false 0", bad: true},
		{out: "(bba{ss}) true false 1 \"unterminated", bad: true},
	} {
		auth, chal, temp, err := ParseBusctlCheck(c.out)
		if (err != nil) != c.bad || (!c.bad && (auth != c.auth || chal != c.chal || temp != c.temp)) {
			t.Errorf("%q: %v %v %v %v", c.out, auth, chal, temp, err)
		}
	}
}

// A grant of an action that asks for the member's own password refuses.
func TestJudgeAuthSelf(t *testing.T) {
	for _, d := range []Default{AuthSelf, AuthSelfKeep} {
		actions := map[string]Action{"org.x.self": {ID: "org.x.self", Any: d, Inactive: d, Active: d}}
		if v := Judge(actions, []Answer{{Action: "org.x.self", Kind: Active, Authorized: true}}, met); v[0].Result != Refuse {
			t.Errorf("%s granted: %s", d, v[0].Result)
		}
	}
}

// pkaction's "-> " is dropped and nothing more: a tab after it stays part
// of the first id, as polkitd's g_strsplit on " " leaves it.
func TestImplyExact(t *testing.T) {
	a, err := ParsePkaction("org.x:\n  implicit any:      no\n  implicit inactive: no\n  implicit active:   no\n  annotation:        org.freedesktop.policykit.imply ->\ta b\n")
	if err != nil || len(a["org.x"].Implies) != 2 || a["org.x"].Implies[0] != "\ta" {
		t.Errorf("%q %v", a["org.x"].Implies, err)
	}
}
