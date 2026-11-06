//go:build windows

package run

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A file mapped writable by another handle, whose file and mapping handles
// are then closed while the view stays, is refused: the view keeps the
// file's write access, so the open with read-only sharing fails, as for a
// file open for writing. (Once held, no writable handle, and so no
// writable mapping, can be made.)
func TestPrepareRefusesAFileWithAWritableView(t *testing.T) {
	exe := helperCopy(t, t.TempDir(), "helper")
	p16, _ := windows.UTF16PtrFromString(exe)
	h, err := windows.CreateFile(p16, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	m, err := windows.CreateFileMapping(h, nil, windows.PAGE_READWRITE, 0, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		t.Fatal(err)
	}
	view, err := windows.MapViewOfFile(m, windows.FILE_MAP_WRITE, 0, 0, 0)
	windows.CloseHandle(m)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Prepare(exe, "")
	if !errors.Is(err, ErrProgramNotFound) || !strings.Contains(err.Error(), "open for writing") {
		t.Fatalf("file with a writable view left: %v, want a refusal", err)
	}
	// With the view gone, it is held.
	windows.UnmapViewOfFile(view)
	p, err := Prepare(exe, "")
	if err != nil {
		t.Fatalf("after the view is unmapped: %v", err)
	}
	p.Close()
}
