//go:build windows

package run

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// platformHelper runs the Windows helper modes; false for an unknown one.
func platformHelper(mode string) bool {
	switch mode {
	case "console":
		// The processes attached to this process's console, if any.
		var pids [64]uint32
		n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
		if n == 0 {
			fmt.Println("none")
			return true
		}
		for _, p := range pids[:min(int(n), len(pids))] {
			fmt.Println(p)
		}
		return true
	case "handle":
		// What the handle value given names here, if anything.
		v, err := strconv.ParseUint(os.Getenv("VETTID_RUN_TEST_HANDLE"), 10, 64)
		if err != nil {
			os.Exit(3)
		}
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n, err := windows.GetFinalPathNameByHandle(windows.Handle(v), &buf[0], uint32(len(buf)), 0)
		if err != nil || n == 0 {
			fmt.Println("invalid")
			return true
		}
		fmt.Println(windows.UTF16ToString(buf[:n]))
		return true
	}
	return false
}
