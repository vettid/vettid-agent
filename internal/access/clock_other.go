//go:build !windows

package access

import "time"

var monoStart = time.Now()

// monoNow is Go's monotonic clock, which stops while the computer sleeps
// on Linux (CLOCK_MONOTONIC) and, as documented, on macOS
// (mach_absolute_time); not measured here.
func monoNow() time.Duration { return time.Since(monoStart) }
