//go:build windows

package protect

import (
	"errors"

	"golang.org/x/sys/windows"
)

// checkPassphraseFD accepts an inherited handle to a pipe or a disk file
// that is not one of the standard handles.
func checkPassphraseFD(fd int) error {
	h := windows.Handle(fd)
	for _, std := range []uint32{windows.STD_INPUT_HANDLE, windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		if s, err := windows.GetStdHandle(std); err == nil && s == h {
			return errors.New("standard input, output and error cannot be used; pass another handle")
		}
	}
	t, err := windows.GetFileType(h)
	if err != nil {
		return errors.New("not an open handle")
	}
	switch t {
	case windows.FILE_TYPE_PIPE, windows.FILE_TYPE_DISK:
		return nil
	default:
		return errors.New("not a pipe or a regular file")
	}
}
