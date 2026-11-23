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

// The kinds of subject (§11.4), by the default polkit judges them by: an
// active local session (allow_active), an inactive local one
// (allow_inactive), and none or one that isn't local, having no seat
// (allow_any).
const (
	Active Kind = iota
	Inactive
	NoSession
)

func (k Kind) String() string {
	return [...]string{"active", "inactive", "any"}[k]
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
	// accepted: granted, and accepted on its own: its default for the
	// subject is yes, or it is allowlisted or recorded yes for that kind.
	accepted bool
}

// Conditions are the facts the conditional entries of §11.4's allowlist
// need. The zero value meets none of them, so those entries refuse.
type Conditions struct {
	// FwupdOnlyTrusted: fwupd's OnlyTrusted isn't off.
	FwupdOnlyTrusted bool
	// LocalSudoRules: nsswitch.conf names no network source (LDAP, sssd)
	// for sudo rules, so every host-scoped rule can be read (and §11.1
	// counts a NOPASSWD rule for any host).
	LocalSudoRules bool
}

// conditional names the allowlist entries that hold only under a
// condition (§11.4), with that condition's name for the report.
var conditional = map[string]func(Conditions) (bool, string){
	"org.freedesktop.fwupd.update-internal":                 func(c Conditions) (bool, string) { return c.FwupdOnlyTrusted, "fwupd's OnlyTrusted is off" },
	"org.freedesktop.hostname1.set-hostname":                func(c Conditions) (bool, string) { return c.LocalSudoRules, "sudo rules come from the network" },
	"org.freedesktop.hostname1.set-static-hostname":         func(c Conditions) (bool, string) { return c.LocalSudoRules, "sudo rules come from the network" },
	"org.freedesktop.NetworkManager.settings.modify.system": func(c Conditions) (bool, string) { return c.LocalSudoRules, "sudo rules come from the network" },
}

// Judge applies §11.4 to every answer, under the allowlist's conditions.
// An unknown action (one the list doesn't hold) is not checked. The
// upgrade-only condition of the allowlisted updates is a release's stock
// test (§13), not an input here.
func Judge(actions map[string]Action, answers []Answer, c Conditions) []Verdict {
	out := make([]Verdict, 0, len(answers))
	for _, ans := range answers {
		out = append(out, judge(actions, ans, c))
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

func judge(actions map[string]Action, ans Answer, c Conditions) Verdict {
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
		if RecordedYes[a.ID][ans.Kind] {
			v.Result, v.Reason, v.accepted = Report, "runs code as root, but its recorded default for "+ans.Kind.String()+" is yes", true
			return v
		}
		v.Result, v.Reason = Refuse, why
		return v
	}
	if def.admin() {
		if why, ok := Allowlist[a.ID]; ok {
			if cond, ok := conditional[a.ID]; ok {
				if met, unmet := cond(c); !met {
					v.Result, v.Reason = Refuse, "allowlisted only while not: "+unmet
					return v
				}
			}
			v.Result, v.Reason, v.accepted = Report, "allowlisted: "+why, true
			return v
		}
		v.Result, v.Reason = Refuse, "an administrator's action ("+string(def)+" for "+ans.Kind.String()+") granted with no password"
		v.adminDefault = true
		return v
	}
	v.Result, v.Reason = Nothing, "its default for "+ans.Kind.String()+" is "+string(def)
	v.accepted = def == Yes
	return v
}

// lift reports two kinds of refusal that follow from other answers
// (proposed for §11.4):
//   - an administrator's action granted only because a grant for the same
//     subject implies it (`org.freedesktop.policykit.imply`) is reported
//     when that grant is accepted on its own: its default for the subject
//     is yes, or it is allowlisted or recorded yes. One level only, as
//     polkitd follows an implication (it doesn't check the implying
//     action's own implications);
//   - an exec.path helper in ExecPathIf runs as root but checks each
//     caller against another action: it is reported while that action
//     asks for an administrator (auth_admin*) of the same subject and
//     grants no other subject asked without one (it asks for an
//     administrator, or refuses outright), since the helper's caller may
//     be any process of the member's.
func lift(actions map[string]Action, vs []Verdict) {
	type key struct{ subject, action string }
	at := map[key]int{}
	for i, v := range vs {
		at[key{v.Subject, v.Action}] = i
	}
	// From the first pass's verdicts only: a lifted grant implies nothing.
	var lifted []int
	for i := range vs {
		v := &vs[i]
		if v.Result != Refuse || !v.adminDefault {
			continue
		}
		for _, a := range actions {
			j, ok := at[key{v.Subject, a.ID}]
			if !ok || !vs[j].accepted {
				continue
			}
			if implies(a, v.Action) {
				v.Reason = "implied by " + a.ID + " (" + string(vs[j].Result) + ")"
				lifted = append(lifted, i)
				break
			}
		}
	}
	for _, i := range lifted {
		vs[i].Result, vs[i].adminDefault = Report, false
	}
	for i := range vs {
		v := &vs[i]
		gate, ok := ExecPathIf[actions[v.Action].ExecPath]
		if v.Result != Refuse || !ok {
			continue
		}
		j, asked := at[key{v.Subject, gate.action}]
		if !asked {
			continue
		}
		adminAsks := func(w Verdict) bool {
			return w.Err == "" && !w.Authorized && w.Challenge && actions[gate.action].defaultFor(w.Kind).admin()
		}
		asks := adminAsks(vs[j])
		for _, w := range vs {
			if w.Action == gate.action && !adminAsks(w) && (w.Err != "" || w.Authorized || w.Challenge) {
				asks = false
			}
		}
		if asks {
			v.Result, v.Reason = Report, gate.why+", while "+gate.action+" asks"
		}
	}
}

// KindFrom is the kind of subject polkitd judged one subject's answers
// by, of the candidates: the one whose defaults account for the most of
// its refusals (a challenge where the default is auth_*, an outright
// refusal where it is no). Grants are never counted: a rule's grant could
// otherwise vote for the kind under which it says nothing. A grant only
// takes a vote away, so under the true kind the count is at least any
// other's; a tie is not ok. counts is per candidate.
func KindFrom(actions map[string]Action, answers []Answer, candidates []Kind) (k Kind, counts []int, ok bool) {
	counts = make([]int, len(candidates))
	for i, c := range candidates {
		for _, a := range answers {
			act, known := actions[a.Action]
			if !known || a.Err != "" || a.Authorized {
				continue
			}
			switch d := act.defaultFor(c); {
			case d == No && !a.Challenge, d != No && d != Yes && a.Challenge:
				counts[i]++
			}
		}
	}
	best, tie := 0, false
	for i := 1; i < len(counts); i++ {
		switch {
		case counts[i] > counts[best]:
			best, tie = i, false
		case counts[i] == counts[best]:
			tie = true
		}
	}
	if len(candidates) == 0 || tie {
		return 0, counts, false
	}
	return candidates[best], counts, true
}

func implies(a Action, id string) bool {
	for _, implied := range a.Implies {
		if implied == id {
			return true
		}
	}
	return false
}

// alwaysRefuses says whether a grant of a refuses whatever its defaults
// (§11.4): it runs code as root, makes a root service, or reaches the
// disk or the packages' trust.
func alwaysRefuses(a Action) (string, bool) {
	if why, ok := AlwaysRefuse[a.ID]; ok {
		return why, true
	}
	for prefix, why := range alwaysRefusePrefix {
		if strings.HasPrefix(a.ID, prefix) {
			return why, true
		}
	}
	if a.ExecPath != "" {
		if allow, ok := ExecActionAllow[a.ID]; ok && allow.path == a.ExecPath {
			return "", false
		}
		if _, ok := ExecPathAllow[a.ExecPath]; ok {
			return "", false
		}
		return "runs " + a.ExecPath + " as root", true
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
	// proposed for §11.4: dnf5daemon's, which Fedora grants wheel
	"org.rpm.dnf.v0.rpm.execute_trusted_transaction": "installs packages, whose scripts run as root (dnf5daemon)",
	"org.rpm.dnf.v0.rpm.Repo.confirm_key":            "trusts a repository's signing key (dnf5daemon)",
}

var alwaysRefusePrefix = map[string]string{
	"org.freedesktop.import1.":    "imports images as root",
	"org.freedesktop.sysupdate1.": "updates the system",
	"org.freedesktop.home1.":      "manages home areas",
}

// RecordedYes names the always-refusing actions whose recorded default is
// yes, and for which kinds of subject (§11.4): a grant of one for such a
// subject is reported, and for another kind refuses.
var RecordedYes = map[string]map[Kind]bool{
	"org.freedesktop.sysupdate1.check": {Active: true},
	// proposed for §11.4: upstream systemd 259's allow_active is yes
	"org.freedesktop.sysupdate1.update":          {Active: true},
	"org.freedesktop.machine1.host-login":        {Active: true},
	"org.freedesktop.home1.update-home-by-owner": {Active: true},
}

// ExecPathAllow names the fixed helpers an exec.path action may run (§11.4).
var ExecPathAllow = map[string]string{
	"/usr/libexec/gsd-backlight-helper":  "GNOME's backlight helper",
	"/usr/libexec/gsd-wacom-oled-helper": "GNOME's Wacom helper",
	"/usr/libexec/gsd-wacom-led-helper":  "GNOME's Wacom helper",
	// proposed for §11.4: a fixed script that only runs fuser on apt's
	// lock files
	"/usr/lib/update-notifier/package-system-locked": "update-notifier's lock check",
	// proposed for §11.4: GNOME 49 and later's backlight helper (mutter's)
	"/usr/libexec/mutter-backlight-helper": "mutter's backlight helper",
	// proposed for §11.4: writes only the XKB lines of
	// /etc/default/keyboard from arguments limited to [a-zA-Z0-9,_:-],
	// then reconfigures keyboard-configuration; locale1.set-keyboard's
	// effect
	"/usr/libexec/gnome-control-center-set-debian-keyboard": "GNOME's keyboard layout (Debian)",
	// §11.4 allowlists org.fedoraproject.thirdparty.opt-out
	"/usr/lib/fedora-third-party/fedora-third-party-opt-out": "Fedora's third-party repositories off",
}

// ExecActionAllow names exec.path actions allowed by id, where the
// helper's other modes (other argv1 values) are other actions that stay
// refused (proposed for §11.4).
// Each is pinned to its helper: the same id with another exec.path refuses.
var ExecActionAllow = map[string]struct{ path, why string }{
	// gnome-software's dkms helper: --test-dkms and --test-akmods only run
	// mokutil --test-key on a fixed key file; --enroll-* stay refused
	"org.gnome.software.dkms-test":   {"/usr/libexec/gnome-software-dkms-helper", "tests whether DKMS's key is enrolled"},
	"org.gnome.software.akmods-test": {"/usr/libexec/gnome-software-dkms-helper", "tests whether akmods' key is enrolled"},
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
	"org.freedesktop.NetworkManager.settings.modify.system":   "system network settings (with local sudo rules)",
	"org.fedoraproject.thirdparty.opt-out":                    "third-party repositories off",
	"org.freedesktop.Flatpak.app-install":                     "Flatpak apps (sandboxed)",
	"org.freedesktop.Flatpak.runtime-install":                 "Flatpak runtimes (sandboxed)",
	"org.freedesktop.Flatpak.app-uninstall":                   "Flatpak apps",
	"org.freedesktop.Flatpak.runtime-uninstall":               "Flatpak runtimes",
	"org.fedoraproject.FirewallD1.info":                       "firewall status (read-only)",
	"org.fedoraproject.FirewallD1.config.info":                "firewall status (read-only)",
	"org.fedoraproject.FirewallD1.direct.info":                "firewall status (read-only)",
	"org.fedoraproject.FirewallD1.policies.info":              "firewall status (read-only)",
	// proposed for §11.4: libmalcontent's rule lets sudo read any
	// account's parental controls
	"com.endlessm.ParentalControls.AppFilter.ReadAny":     "parental controls (read-only)",
	"com.endlessm.ParentalControls.SessionLimits.ReadAny": "parental controls (read-only)",
	"org.freedesktop.Malcontent.WebFilter.ReadAny":        "parental controls (read-only)",
	// proposed for §11.4, with its fixed helper above
	"org.gnome.controlcenter.set-keyboard": "the keyboard layout (Debian)",
}
