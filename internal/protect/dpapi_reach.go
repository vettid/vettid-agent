package protect

import "log/slog"

// How far a Windows user's DPAPI keys reach beyond this computer (owner
// decision, 2026-10-18). User-scope DPAPI binds the state file's key to
// this computer only for a local account, or a Microsoft account,
// without a roaming profile: a roaming profile carries the user's DPAPI
// master keys to the other computers where it is loaded, and in an
// Active Directory domain the domain's DPAPI backup key recovers a domain
// user's master keys (Microsoft's CryptProtectData remarks). The
// connector does not refuse such an account; `pair` (when DPAPI is
// chosen) and `status` show a notice for each case detected.
//
// Detection is best effort: a check that fails gives no notice and a
// debug log only, never an error.

// Notices for the operator (chosen; AGENT-PLAN §11 drafts none).
const (
	TextDPAPIDomain  = "This Windows account is a domain account: your organization can recover keys protected for it."
	TextDPAPIRoaming = "This Windows account has a roaming profile: keys protected for it also open on the other computers where your profile is loaded."
)

// The checks DPAPINotices runs; tests replace them. Each reports
// whether its case applies to the current Windows user.
var (
	detectDomainAccount  = domainAccount
	detectRoamingProfile = roamingProfile
)

// DPAPINotices returns the notices that apply to the current Windows
// user's DPAPI keys, in a fixed order (domain, then roaming), or none.
// On other systems it returns none.
func DPAPINotices() []string {
	var out []string
	if ok, err := detectDomainAccount(); err != nil {
		slog.Debug("DPAPI: could not tell whether this is a domain account", "err", err)
	} else if ok {
		out = append(out, TextDPAPIDomain)
	}
	if ok, err := detectRoamingProfile(); err != nil {
		slog.Debug("DPAPI: could not tell whether this account has a roaming profile", "err", err)
	} else if ok {
		out = append(out, TextDPAPIRoaming)
	}
	return out
}
