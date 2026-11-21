//go:build !windows

package run

import (
	"fmt"
	"os"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
)

// platformHelper runs the POSIX helper modes; false for an unknown one.
func platformHelper(mode string) bool {
	switch mode {
	case "tty":
		// Its session, and whether it has a controlling terminal.
		sid, _ := unix.Getsid(0)
		tty := "none"
		if f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
			f.Close()
			tty = "open"
		}
		fmt.Printf("sid=%d pid=%d tty=%s\n", sid, os.Getpid(), tty)
		return true
	case "fds":
		// Whether any descriptor from 3 up is the file the test named.
		var want unix.Stat_t
		if err := unix.Stat(os.Getenv("VETTID_RUN_TEST_LEAK"), &want); err != nil {
			os.Exit(3)
		}
		dir := "/dev/fd"
		if runtime.GOOS == "linux" {
			dir = "/proc/self/fd"
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			os.Exit(4)
		}
		out := "clean"
		for _, e := range ents {
			fd, err := strconv.Atoi(e.Name())
			if err != nil || fd < 3 {
				continue
			}
			var st unix.Stat_t
			if unix.Fstat(fd, &st) == nil && st.Dev == want.Dev && st.Ino == want.Ino {
				out = "leaked"
			}
		}
		fmt.Println(out)
		return true
	}
	return false
}
