//go:build windows

package access

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procQueryUnbiasedInterruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryUnbiasedInterruptTime")

// monoNow is a monotonic clock that stops while the computer sleeps:
// QueryUnbiasedInterruptTime, in 100 ns units. Go's own monotonic clock
// on Windows (the interrupt time) counts the sleep too, so it would never
// move apart from the wall clock across one. If the call fails, Go's
// clock is used, and a sleep is then caught by the service's power event
// only.
func monoNow() time.Duration {
	var t uint64
	if r, _, _ := procQueryUnbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&t))); r != 0 {
		return time.Duration(t) * 100
	}
	return time.Since(monoStart)
}

var monoStart = time.Now()
