//go:build linux

package protect

// namedFIFO: on Linux the mode rule applies to every pipe. Anonymous
// pipes are mode 0600, owned by the process that made them, and pass.
func namedFIFO(int) bool { return true }
