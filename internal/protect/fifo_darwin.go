//go:build darwin

package protect

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// namedFIFO reports whether the pipe on fd is a FIFO on disk. macOS
// reports anonymous pipes with a permissive mode, so the mode rule
// applies only to a pipe that has a path: fcntl(F_GETPATH) succeeds for
// a FIFO on disk and fails for an anonymous pipe.
func namedFIFO(fd int) bool {
	buf := make([]byte, unix.PathMax)
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&buf[0]))))
	runtime.KeepAlive(buf)
	return err == nil
}
