//go:build darwin

package protect

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getpathBuf receives fcntl(F_GETPATH) results. It is a package-level
// array, so it never lives on a goroutine stack that could move while
// the kernel writes into it; getpathMu serializes its use.
var (
	getpathMu  sync.Mutex
	getpathBuf [unix.PathMax]byte
)

// namedFIFO reports whether the pipe on fd is a FIFO on disk. macOS
// reports anonymous pipes with a permissive mode, so the mode rule
// applies only to a pipe that has a path: fcntl(F_GETPATH) succeeds for
// a FIFO on disk and fails for an anonymous pipe.
func namedFIFO(fd int) bool {
	getpathMu.Lock()
	defer getpathMu.Unlock()
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&getpathBuf[0]))))
	clear(getpathBuf[:])
	return err == nil
}
