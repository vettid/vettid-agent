//go:build !linux && !darwin

package fingerprint

// collectPlatformAttributes is a no-op on unsupported platforms.
// The fingerprint will be based on hostname only (collected in machine.go).
// For containers/cloud VMs on unsupported platforms, use --platform-key-file.
func collectPlatformAttributes(attrs *MachineAttributes) {
	// No platform-specific collection available
}
