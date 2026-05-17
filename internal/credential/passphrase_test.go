package credential

import "testing"

func TestValidatePassphraseStrength(t *testing.T) {
	cases := []struct {
		name      string
		pass      string
		expectErr bool
	}{
		{"empty", "", true},
		{"too-short-but-strong", "Aa1!Bb2@", true}, // 8 chars
		{"length-only-no-classes", "aaaaaaaaaaaa", true},
		{"two-classes-long-enough", "aaaaaaaaaaaa1", true}, // 13 chars but only lower+digit
		{"three-classes-12-chars", "abcDEF123456", false},
		{"four-classes", "abcDEF12345!", false},
		{"common-strong", "TheCorrectHorse42Stapled!", false},
		{"unicode-classes", "Pässwörd123!", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassphraseStrength([]byte(tc.pass))
			if tc.expectErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.pass)
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.pass, err)
			}
		})
	}
}

func TestValidatePassphraseStrength_DoesNotEchoPassphrase(t *testing.T) {
	// Regression: the error message must NOT include the user's
	// passphrase text — error strings get logged.
	const pw = "secret-that-must-not-leak"
	err := ValidatePassphraseStrength([]byte(pw))
	if err == nil {
		t.Fatalf("expected this short pass to fail")
	}
	if contains(err.Error(), pw) {
		t.Errorf("error message echoed passphrase: %q", err.Error())
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
