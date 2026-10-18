//go:build windows

package protect

import "github.com/vettid/vettid-agent/internal/state"

// Platform returns the platform protector named name (a state file
// header's protector, or Choice.Protector) for the state directory dir
// (unused here: this protector keeps nothing outside the state file),
// or nil if this build has no platform protector of that name. The
// passphrase protector is not a platform protector: it needs the
// passphrase (NewPassphrase).
func Platform(name, dir string) state.Protector {
	if name == DPAPIName {
		return NewDPAPI()
	}
	return nil
}

// All returns one instance of every protector this build knows, for
// state.Store.WipeAll (on the state directory dir, unused here) when a
// state file's protector cannot be determined. The passphrase instance holds no passphrase: it can only
// Wipe (which deletes nothing).
func All(dir string) []state.Protector {
	return []state.Protector{NewDPAPI(), &Passphrase{}}
}
