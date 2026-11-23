// Package admincheck holds the Linux administrator checks of
// AGENT-LINUX-RUNTIME §11. This file is §11.4's polkit rule: given the
// actions polkit lists and polkitd's answers for the member's subjects,
// which grants refuse the member, which are reported, and which say
// nothing. It is pure; gathering the answers is the caller's (the run
// helper, install and the elevated status; for now the measurement test).
package admincheck

import (
	"sort"
	"strings"
)

// Default is one of polkit's implicit authorizations.
type Default string

// The implicit authorizations (polkit's `allow_*` values).
const (
	No            Default = "no"
	Yes           Default = "yes"
	AuthSelf      Default = "auth_self"
	AuthSelfKeep  Default = "auth_self_keep"
	AuthAdmin     Default = "auth_admin"
	AuthAdminKeep Default = "auth_admin_keep"
)

func (d Default) admin() bool { return d == AuthAdmin || d == AuthAdminKeep }

// Kind is the kind of subject polkit judged an answer for.
type Kind int

// The kinds of subject (§11.4): an active local session, an inactive one,
// and none.
const (
	Active Kind = iota
	Inactive
	NoSession
)

func (k Kind) String() string {
	return [...]string{"active", "inactive", "no session"}[k]
}

// Action is one action polkit lists, with its shipped defaults, its
// `org.freedesktop.policykit.exec.path` annotation, if any, and the
// actions its `org.freedesktop.policykit.imply` annotation names (a
// subject authorized for it is authorized for them too).
type Action struct {
	ID                    string
	Any, Inactive, Active Default
	ExecPath              string
	Implies               []string
}

func (a Action) defaultFor(k Kind) Default {
	switch k {
	case Active:
		return a.Active
	case Inactive:
		return a.Inactive
	}
	return a.Any
}

// Answer is polkitd's answer to CheckAuthorization, with no user
// interaction, for one action and one subject.
type Answer struct {
	Action     string
	Kind       Kind   // the kind of subject polkit judged
	Subject    string // for the report: the session id, or "no session"
	Authorized bool
	Challenge  bool
	Temporary  bool // the details carry polkit.temporary_authorization_id
	Err        string
}

// Result is what one answer means for the member.
type Result string

// The results: a grant that makes the member an administrator, one that
// is reported, one that could not be checked, and nothing.
const (
	Refuse     Result = "refuse"
	Report     Result = "report"
	NotChecked Result = "not_checked"
	Nothing    Result = "nothing"
)

// Verdict is the result for one answer, with its reason.
type Verdict struct {
	Answer
	Result Result
	Reason string
	// adminDefault: refused only as an administrator's action granted
	// with no password, so a grant implied by an accepted one may lift it.
	adminDefault bool
}

// Judge applies §11.4 to every answer. An unknown action (one the list
// doesn't hold) is not checked.
func Judge(actions map[string]Action, answers []Answer) []Verdict {
	out := make([]Verdict, 0, len(answers))
	for _, ans := range answers {
		out = append(out, judge(actions, ans))
	}
	lift(actions, out)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Result != out[j].Result {
			return rank(out[i].Result) < rank(out[j].Result)
		}
		return out[i].Action < out[j].Action
	})
	return out
}

func rank(r Result) int {
	return map[Result]int{Refuse: 0, NotChecked: 1, Report: 2, Nothing: 3}[r]
}

func judge(actions map[string]Action, ans Answer) Verdict {
	v := Verdict{Answer: ans}
	a, known := actions[ans.Action]
	switch {
	case ans.Err != "":
		v.Result, v.Reason = NotChecked, "polkitd: "+ans.Err
		return v
	case !known:
		v.Result, v.Reason = NotChecked, "an action polkit doesn't list"
		return v
	case !ans.Authorized:
		v.Result, v.Reason = Nothing, "not granted without a password"
		return v
	case ans.Temporary:
		v.Result, v.Reason = Report, "a kept authorization (a caching window)"
		return v
	}
	def := a.defaultFor(ans.Kind)
	if why, ok := alwaysRefuses(a); ok {
		if RecordedYes[a.ID] {
			v.Result, v.Reason = Report, "runs code as root, but its recorded default is yes"
			return v
		}
		v.Result, v.Reason = Refuse, why
		return v
	}
	if def.admin() {
		if why, ok := Allowlist[a.ID]; ok {
			v.Result, v.Reason = Report, "allowlisted: "+why
			return v
		}
		v.Result, v.Reason = Refuse, "an administrator's action ("+string(def)+" for "+ans.Kind.String()+") granted with no password"
		v.adminDefault = true
		return v
	}
	v.Result, v.Reason = Nothing, "its default for "+ans.Kind.String()+" is "+string(def)
	return v
}

// lift reports two kinds of refusal that follow from another answer for
// the same subject (proposed for §11.4):
//   - an administrator's action granted only because an accepted grant
//     implies it (`org.freedesktop.policykit.imply`) is judged as that
//     grant: reported when that grant is accepted (allowlisted, or its
//     own default for the subject), followed through chains of
//     implication;
//   - an exec.path helper in ExecPathIf runs as root but checks each
//     caller against another action: it is reported while that action
//     still challenges for an administrator (auth_admin*) for the same
//     subject.
func lift(actions map[string]Action, vs []Verdict) {
	type key struct{ subject, action string }
	at := map[key]int{}
	for i, v := range vs {
		at[key{v.Subject, v.Action}] = i
	}
	for changed := true; changed; {
		changed = false
		for i := range vs {
			v := &vs[i]
			if v.Result != Refuse || !v.adminDefault {
				continue
			}
			for _, a := range actions {
				j, ok := at[key{v.Subject, a.ID}]
				if !ok || !vs[j].Authorized || vs[j].Result == Refuse || vs[j].Result == NotChecked {
					continue
				}
				for _, implied := range a.Implies {
					if implied == v.Action {
						v.Result, v.Reason, v.adminDefault = Report, "implied by "+a.ID+" ("+string(vs[j].Result)+")", false
						changed = true
					}
				}
				if v.Result == Report {
					break
				}
			}
		}
	}
	for i := range vs {
		v := &vs[i]
		gate, ok := ExecPathIf[actions[v.Action].ExecPath]
		if v.Result != Refuse || !ok {
			continue
		}
		if j, ok := at[key{v.Subject, gate.action}]; ok && vs[j].Err == "" && !vs[j].Authorized && vs[j].Challenge &&
			actions[gate.action].defaultFor(vs[j].Kind).admin() {
			v.Result, v.Reason = Report, gate.why+", while "+gate.action+" asks"
		}
	}
}

// alwaysRefuses says whether a grant of a refuses whatever its defaults
// (§11.4): it runs code as root, makes a root service, or reaches the
// disk or the packages' trust.
func alwaysRefuses(a Action) (string, bool) {
	if a.ExecPath != "" {
		if _, ok := ExecPathAllow[a.ExecPath]; ok {
			return "", false
		}
		return "runs " + a.ExecPath + " as root", true
	}
	if why, ok := AlwaysRefuse[a.ID]; ok {
		return why, true
	}
	for prefix, why := range alwaysRefusePrefix {
		if strings.HasPrefix(a.ID, prefix) {
			return why, true
		}
	}
	return "", false
}

// AlwaysRefuse names the actions that refuse whatever their defaults.
var AlwaysRefuse = map[string]string{
	"org.freedesktop.policykit.exec":                          "pkexec: any program as root",
	"org.freedesktop.systemd1.manage-units":                   "starts units as root",
	"org.freedesktop.systemd1.manage-unit-files":              "installs units",
	"org.freedesktop.systemd1.set-environment":                "sets root services' environment",
	"org.freedesktop.machine1.host-shell":                     "a root shell on the host",
	"org.freedesktop.machine1.host-login":                     "a login on the host",
	"org.freedesktop.machine1.shell":                          "a shell in a machine",
	"org.freedesktop.machine1.login":                          "a login in a machine",
	"org.freedesktop.machine1.manage-machines":                "manages machines",
	"org.freedesktop.machine1.manage-images":                  "manages machine images",
	"org.freedesktop.portable1.attach-images":                 "attaches portable services",
	"org.freedesktop.udisks2.open-device-system":              "raw access to a system disk",
	"org.freedesktop.udisks2.modify-device-system":            "modifies a system disk",
	"org.freedesktop.udisks2.modify-system-configuration":     "changes system disk configuration",
	"org.libvirt.unix.manage":                                 "manages VMs as root",
	"org.freedesktop.packagekit.package-install-untrusted":    "installs untrusted packages",
	"org.freedesktop.packagekit.package-downgrade":            "installs older packages",
	"org.freedesktop.packagekit.system-sources-configure":     "configures package sources",
	"org.freedesktop.packagekit.system-trust-signing-key":     "trusts a signing key",
	"org.freedesktop.packagekit.package-install":              "installs packages, whose scripts run as root (Fedora's B)",
	"org.freedesktop.packagekit.package-remove":               "removes packages (Fedora's B)",
	"org.debian.apt.install-file":                             "installs a package file",
	"org.debian.apt.install-or-remove-packages":               "installs or removes packages",
	"org.debian.apt.change-repository":                        "changes package sources",
	"io.snapcraft.snapd.manage":                               "manages snaps",
	"org.freedesktop.accounts.user-administration":            "administers accounts",
	"org.fedoraproject.FirewallD1.all":                        "firewall: everything",
	"org.fedoraproject.FirewallD1.config":                     "firewall: configuration as root",
	"org.fedoraproject.FirewallD1.direct":                     "firewall: raw rules as root",
	"org.fedoraproject.FirewallD1.policies":                   "firewall: policies",
	"org.opensuse.cupspkhelper.mechanism.all-edit":            "adds a printer from a file read as root",
	"org.opensuse.cupspkhelper.mechanism.printeraddremove":    "adds a printer from a file read as root",
	"org.opensuse.cupspkhelper.mechanism.printer-local-edit":  "adds a printer from a file read as root",
	"org.opensuse.cupspkhelper.mechanism.printer-remote-edit": "adds a printer from a file read as root",
	"org.opensuse.cupspkhelper.mechanism.server-settings":     "replaces cupsd.conf (chosen)",
}

var alwaysRefusePrefix = map[string]string{
	"org.freedesktop.import1.":    "imports images as root",
	"org.freedesktop.sysupdate1.": "updates the system",
	"org.freedesktop.home1.":      "manages home areas",
}

// RecordedYes names the always-refusing actions whose recorded default is
// yes (§11.4): a grant of one is reported.
var RecordedYes = map[string]bool{
	"org.freedesktop.sysupdate1.check": true,
}

// ExecPathAllow names the fixed helpers an exec.path action may run (§11.4).
var ExecPathAllow = map[string]string{
	"/usr/libexec/gsd-backlight-helper":  "GNOME's backlight helper",
	"/usr/libexec/gsd-wacom-oled-helper": "GNOME's Wacom helper",
	"/usr/libexec/gsd-wacom-led-helper":  "GNOME's Wacom helper",
	// proposed for §11.4: a fixed script that only runs fuser on apt's
	// lock files
	"/usr/lib/update-notifier/package-system-locked": "update-notifier's lock check",
}

// ExecPathIf names the exec.path helpers that run as root but check each
// caller against another action of their own (proposed for §11.4).
var ExecPathIf = map[string]struct{ action, why string }{
	"/usr/libexec/gvfsd-admin": {"org.gtk.vfs.file-operations", "gvfs's admin backend"},
}

// Allowlist names the stock grants of an administrator's action measured
// not to run a program the member chooses as root (§11.4).
var Allowlist = map[string]string{
	"org.freedesktop.udisks2.filesystem-mount-system":         "mounts a system disk (nosuid)",
	"org.freedesktop.udisks2.encrypted-unlock-system":         "unlocks a system disk",
	"org.freedesktop.udisks2.filesystem-fstab":                "mounts an fstab entry",
	"org.freedesktop.timedate1.set-time":                      "the time",
	"org.freedesktop.timedate1.set-timezone":                  "the time zone",
	"org.freedesktop.timedate1.set-local-rtc":                 "the hardware clock",
	"org.freedesktop.timedate1.set-ntp":                       "network time",
	"org.gnome.controlcenter.datetime.configure":              "the date and time",
	"com.canonical.controlcenter.datetime.configure":          "the date and time",
	"org.kde.kcontrol.kcmclock.save":                          "the date and time",
	"org.mate.settingsdaemon.datetimemechanism.settime":       "the date and time",
	"org.freedesktop.locale1.set-locale":                      "the locale",
	"org.freedesktop.locale1.set-keyboard":                    "the keyboard",
	"org.freedesktop.bolt.enroll":                             "Thunderbolt devices",
	"org.freedesktop.bolt.authorize":                          "Thunderbolt devices",
	"org.freedesktop.bolt.manage":                             "Thunderbolt devices",
	"org.freedesktop.fwupd.update-internal":                   "signed firmware (while OnlyTrusted)",
	"org.freedesktop.login1.hibernate":                        "hibernation",
	"org.freedesktop.login1.handle-hibernate-key":             "hibernation",
	"org.freedesktop.login1.hibernate-multiple-sessions":      "hibernation",
	"org.freedesktop.upower.hibernate":                        "hibernation",
	"org.gnome.cpufreqselector":                               "the CPU frequency",
	"org.mate.cpufreqselector":                                "the CPU frequency",
	"com.ubuntu.whoopsiepreferences.change":                   "crash-report preferences",
	"org.opensuse.cupspkhelper.mechanism.class-edit":          "printer classes",
	"org.opensuse.cupspkhelper.mechanism.devices-get":         "lists printer devices",
	"org.opensuse.cupspkhelper.mechanism.job-edit":            "print jobs",
	"org.opensuse.cupspkhelper.mechanism.job-not-owned-edit":  "print jobs",
	"org.opensuse.cupspkhelper.mechanism.printer-enable":      "enables a printer",
	"org.opensuse.cupspkhelper.mechanism.printer-set-default": "the default printer",
	"org.freedesktop.hostname1.set-hostname":                  "the host name (with the any-host sudo rule)",
	"org.freedesktop.hostname1.set-static-hostname":           "the host name (with the any-host sudo rule)",
	"org.freedesktop.packagekit.upgrade-system":               "upgrades (upgrade-only)",
	"org.freedesktop.packagekit.system-update":                "updates (upgrade-only)",
	"org.freedesktop.packagekit.trigger-offline-update":       "offline updates (upgrade-only)",
	"org.freedesktop.packagekit.trigger-offline-upgrade":      "offline upgrades (upgrade-only)",
	"org.debian.apt.upgrade-packages":                         "upgrades (upgrade-only)",
	"org.freedesktop.NetworkManager.settings.modify.system":   "system network settings",
	"org.fedoraproject.thirdparty.opt-out":                    "third-party repositories off",
	"org.freedesktop.Flatpak.app-install":                     "Flatpak apps (sandboxed)",
	"org.freedesktop.Flatpak.runtime-install":                 "Flatpak runtimes (sandboxed)",
	"org.freedesktop.Flatpak.app-uninstall":                   "Flatpak apps",
	"org.freedesktop.Flatpak.runtime-uninstall":               "Flatpak runtimes",
	"org.fedoraproject.FirewallD1.info":                       "firewall status (read-only)",
	"org.fedoraproject.FirewallD1.config.info":                "firewall status (read-only)",
	"org.fedoraproject.FirewallD1.direct.info":                "firewall status (read-only)",
	"org.fedoraproject.FirewallD1.policies.info":              "firewall status (read-only)",
}
