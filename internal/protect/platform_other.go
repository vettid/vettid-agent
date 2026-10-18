//go:build !linux && !windows && !(darwin && cgo)

package protect

import "github.com/vettid/vettid-agent/internal/state"

// Platform returns the platform protector named name, or nil: this
// build has no platform protector (on macOS: a build without cgo, which
// the Keychain protector needs).
func Platform(name, dir string) state.Protector { return nil }

// All returns one instance of every protector this build knows, for
// state.Store.WipeAll. The passphrase instance holds no passphrase: it
// can only Wipe (which deletes nothing).
func All(dir string) []state.Protector {
	return []state.Protector{&Passphrase{}}
}
