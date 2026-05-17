package credential

import (
	"fmt"
	"unicode"
)

// SECURITY (#60): minimum passphrase strength required by Save() /
// Load(). The credential blob is sealed with
// Argon2id(passphrase || platform_key); the platform_key adds machine
// binding but it is recoverable by anyone with the device, so the
// passphrase is the only thing standing between an attacker who has
// captured the credential file and the connection key inside.
//
// Argon2id at the configured params (~3 iterations, 64 MiB) costs a
// modern CPU about 250 ms per guess. For a passphrase to defeat
// minutes-to-hours of offline brute-force against a captured file,
// it needs > 50 bits of effective entropy. We require:
//
//   • length >= 12 chars (the trade-off floor below which any
//     additional class requirement still leaves the space too small),
//   • at least 3 of 4 character classes (lower, upper, digit, symbol).
//
// These rules match the OWASP "level 2" memorised-secret guidance.
// Reject is fail-closed: the caller cannot opt out, only generate a
// stronger passphrase.

const (
	minPassphraseLength = 12
	minCharClasses      = 3
)

// ValidatePassphraseStrength returns nil when the passphrase is
// acceptable. Any error returned is safe to surface to the user — it
// describes the missing requirement without echoing the passphrase
// itself.
func ValidatePassphraseStrength(pass []byte) error {
	if len(pass) < minPassphraseLength {
		return fmt.Errorf("passphrase too short: must be at least %d characters", minPassphraseLength)
	}

	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range string(pass) {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r) || unicode.IsSpace(r):
			hasSymbol = true
		}
	}

	classes := 0
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if b {
			classes++
		}
	}
	if classes < minCharClasses {
		return fmt.Errorf(
			"passphrase too simple: must include at least %d of {lowercase, uppercase, digit, symbol}; got %d",
			minCharClasses, classes,
		)
	}

	return nil
}
