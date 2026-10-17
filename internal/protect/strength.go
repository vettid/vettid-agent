package protect

import (
	"fmt"
	"unicode"
	"unicode/utf8"
)

// CheckStrength applies the strength rules for a new passphrase
// (AGENT-PLAN §1, from the 2026-05 connector): at least MinChars
// characters and at least MinClasses of four classes: lower-case
// letters, upper-case letters, decimal digits, and symbols, punctuation
// or letters without case. Spaces and combining marks are allowed but
// count for no class. Characters are counted after normalization to NFC
// (chosen; not in the spec).
//
// Refused (chosen; not in the spec), because they cannot be seen or
// typed reliably: control characters (Cc: a pasted line break, a tab),
// format characters (Cf: zero-width space, byte order mark, bidi marks),
// private-use (Co), surrogates (Cs) and unassigned code points (Cn), and
// line and paragraph separators. The error says which rule failed and
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
	for n := 0; n < len(s); {
		r, size := utf8.DecodeRune(s[n:])
		n += size
		switch {
		case unicode.IsControl(r):
			return fmt.Errorf("%w: it contains a control character such as a line break or tab", ErrWeakPassphrase)
		case unicode.Is(unicode.Cf, r):
			return fmt.Errorf("%w: it contains an invisible formatting character (such as a zero-width space or a direction mark)", ErrWeakPassphrase)
		case unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r), !unicode.IsGraphic(r):
			// !IsGraphic, after the cases above, is unassigned code
			// points and line or paragraph separators.
			return fmt.Errorf("%w: it contains a character that is unassigned, private-use or not visible", ErrWeakPassphrase)
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsSymbol(r), unicode.IsPunct(r), unicode.IsLetter(r):
			other = true
		}
	}
	if utf8.RuneCount(s) < MinChars {
		return fmt.Errorf("%w: use at least %d characters", ErrWeakPassphrase, MinChars)
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	if classes < MinClasses {
		return fmt.Errorf("%w: use at least %d of these: lower-case letters, upper-case letters, digits, symbols or punctuation",
			ErrWeakPassphrase, MinClasses)
	}
	return nil
}
