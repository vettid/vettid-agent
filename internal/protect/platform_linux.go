//go:build linux

package protect

import "github.com/vettid/vettid-agent/internal/state"

// Platform returns the platform protector named name (a state file
// header's protector, or Choice.Protector), or nil if this build has no
// platform protector of that name. The passphrase protector is not a
// platform protector: it needs the passphrase (NewPassphrase).
func Platform(name string) state.Protector {
	if name == TPMName {
		return NewTPM(DefaultTPMDevice)
	}
	return nil
}

// All returns one instance of every protector this build knows, for
// state.Store.WipeAll when a state file's protector cannot be
// determined. The passphrase instance holds no passphrase: it can only
// Wipe (which deletes nothing).
func All() []state.Protector {
	return []state.Protector{NewTPM(DefaultTPMDevice), &Passphrase{}}
}
