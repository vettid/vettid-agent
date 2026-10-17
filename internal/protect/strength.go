package protect

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// CheckStrength applies the strength rules for a new passphrase
// (AGENT-PLAN §1, from the 2026-05 connector): at least MinChars
// characters and at least MinClasses of the four classes lower-case
// letters, upper-case letters, digits and other characters. Characters
// are counted after normalization to NFC. Control characters (a pasted
// line break, a tab) are refused. The error says which rule failed and
// never contains the passphrase.
func CheckStrength(pass []byte) error {
	if !utf8.Valid(pass) {
		return fmt.Errorf("%w: it is not valid UTF-8 text", ErrWeakPassphrase)
	}
	if len(pass) > MaxBytes {
		return fmt.Errorf("%w: it is longer than %d bytes", ErrWeakPassphrase, MaxBytes)
	}
	s := nfcCopy(pass)
	defer clear(s)
	var lower, upper, digit, other bool
	n := 0
	for len(s[n:]) > 0 {
		r, size := utf8.DecodeRune(s[n:])
		n += size
		switch {
		case unicode.IsControl(r):
			return fmt.Errorf("%w: it contains a control character such as a line break or tab", ErrWeakPassphrase)
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	if c := utf8.RuneCount(s); c < MinChars {
		return fmt.Errorf("%w: use at least %d characters", ErrWeakPassphrase, MinChars)
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	if classes < MinClasses {
		return fmt.Errorf("%w: use at least %d of these: lower-case letters, upper-case letters, digits, other characters",
			ErrWeakPassphrase, MinClasses)
	}
	return nil
}
