//go:build linux

package protect

import "syscall"

// namedFIFO: on Linux every pipe is checked; anonymous pipes are mode
// 0600 and pass.
func namedFIFO(*syscall.Stat_t) bool { return true }
