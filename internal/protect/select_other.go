//go:build !linux && !windows

package protect

import "runtime"

// ChooseProtector: no platform protector is built for this system yet
// (AGENT-PLAN §6 A1.5 macOS Keychain), so the
// passphrase protector is chosen.
func ChooseProtector(ChooseOptions) (Choice, error) {
	return Choice{
		Protector: PassphraseName,
		Reason:    "no platform protector in this build for " + runtime.GOOS + " yet; using a passphrase",
	}, nil
}
