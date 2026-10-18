//go:build !linux && !windows && !(darwin && cgo)

package protect

import "runtime"

// ChooseProtector: no platform protector is built for this system (on
// macOS: a build without cgo, which the Keychain protector needs), so
// the passphrase protector is chosen.
func ChooseProtector(ChooseOptions) (Choice, error) {
	reason := "no platform protector in this build for " + runtime.GOOS
	if runtime.GOOS == "darwin" {
		reason = "this vettid-agent build was made without cgo, so it cannot use the macOS Keychain (only the signed vettid-agent app can)"
	}
	return Choice{Protector: PassphraseName, Reason: reason + "; using a passphrase"}, nil
}
