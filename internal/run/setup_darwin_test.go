//go:build darwin

package run

// platformTestSetup turns on the separate-account switch, so the tests
// exercise the macOS copy; TestStartRefusedOnMacOSWithoutSeparateAccount
// turns it off.
func platformTestSetup() { separateAccount = true }
