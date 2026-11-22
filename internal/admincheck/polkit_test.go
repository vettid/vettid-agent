package admincheck

import "testing"

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
	if len(a) != 7 {
		t.Errorf("%d actions, want 7", len(a))
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
	for _, v := range Judge(actions, answers) {
		if w := want[v.Action+"/"+v.Kind.String()]; v.Result != w {
			t.Errorf("%s (%s): %s (%s), want %s", v.Action, v.Kind, v.Result, v.Reason, w)
		}
	}
}
