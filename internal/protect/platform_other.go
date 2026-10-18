//go:build !linux && !windows

package protect

import "github.com/vettid/vettid-agent/internal/state"

// Platform returns the platform protector named name, or nil: this
// build has no platform protector for this system yet (AGENT-PLAN §6
// A1.5 macOS Keychain).
func Platform(name string) state.Protector { return nil }

// All returns one instance of every protector this build knows, for
// state.Store.WipeAll. The passphrase instance holds no passphrase: it
// can only Wipe (which deletes nothing).
func All() []state.Protector {
	return []state.Protector{&Passphrase{}}
}
