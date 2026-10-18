package protect

import (
	"bytes"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// withReach replaces the DPAPI reach checks for one test.
func withReach(t *testing.T, domain, roaming func() (bool, error)) {
	t.Helper()
	d, r := detectDomainAccount, detectRoamingProfile
	detectDomainAccount, detectRoamingProfile = domain, roaming
	t.Cleanup(func() { detectDomainAccount, detectRoamingProfile = d, r })
}

func answer(ok bool, err error) func() (bool, error) {
	return func() (bool, error) { return ok, err }
}

// TestDPAPINotices: one notice per case detected, in a fixed order; a
// check that fails gives no notice and a debug log only.
func TestDPAPINotices(t *testing.T) {
	broken := errors.New("access denied")
	for _, tc := range []struct {
		name            string
		domain, roaming func() (bool, error)
		want            []string
		logged          int
	}{
		{"local", answer(false, nil), answer(false, nil), nil, 0},
		{"domain", answer(true, nil), answer(false, nil), []string{TextDPAPIDomain}, 0},
		{"roaming", answer(false, nil), answer(true, nil), []string{TextDPAPIRoaming}, 0},
		{"both", answer(true, nil), answer(true, nil), []string{TextDPAPIDomain, TextDPAPIRoaming}, 0},
		{"domain check fails", answer(true, broken), answer(true, nil), []string{TextDPAPIRoaming}, 1},
		{"roaming check fails", answer(true, nil), answer(true, broken), []string{TextDPAPIDomain}, 1},
		{"both checks fail", answer(false, broken), answer(false, broken), nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withReach(t, tc.domain, tc.roaming)
			var buf bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(old)
			got := DPAPINotices()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("notices %q, want %q", got, tc.want)
			}
			logs := buf.String()
			if n := strings.Count(logs, "level=DEBUG"); n != tc.logged || strings.Count(logs, "level=") != n {
				t.Errorf("logs: %q", logs)
			}
		})
	}
}
