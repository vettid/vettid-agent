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

org.gnome.software.akmods-test:
  implicit any:      yes
  implicit inactive: yes
  implicit active:   yes
  annotation:        org.freedesktop.policykit.exec.path -> /usr/libexec/another-helper

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
