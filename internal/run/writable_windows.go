//go:build windows

package run

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procAccessCheck = windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck")

// genericMapping is Windows' GENERIC_MAPPING.
type genericMapping struct {
	GenericRead, GenericWrite, GenericExecute, GenericAll uint32
}

// Rights over a directory that let its holder change which program a name
// in it finds: add a file or directory, delete or rename an entry, delete
// the directory, or change its access or owner.
const (
	fileAddFile         = 0x0002
	fileAddSubdirectory = 0x0004
	fileDeleteChild     = 0x0040
	maximumAllowed      = 0x02000000

	dirRights = fileAddFile | fileAddSubdirectory | fileDeleteChild |
		windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
	// For a parent, adding entries doesn't change this path (every user may
	// create folders in C:\), but renaming or deleting one does.
	// (chosen; not in the spec)
	parentRights = fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
)

// writable reports whether the connector's own user (its token, with its
// groups) holds a right over dir that lets it change what dir holds: as the
// directory itself (parent false) or as one of a --run-path's parents.
func writable(dir string, parent bool) (bool, error) {
	// A junction or other reparse point is refused outright: links were
	// resolved before this, but junctions aren't (Go 1.23+), and the
	// security read below would describe its target, which its owner can
	// change later.
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return false, fmt.Errorf("is not a valid path")
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return false, fmt.Errorf("can't be checked: %w", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("is a junction or link; use the directory it points to")
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("its access can't be read: %w", err)
	}
	granted, err := maxAllowed(sd)
	if err != nil {
		return false, err
	}
	want := uint32(dirRights)
	if parent {
		want = parentRights
	}
	return granted&want != 0, nil
}

// maxAllowed is what the current user may do with an object of sd,
// owner's implicit rights included (AccessCheck with MAXIMUM_ALLOWED and
// an impersonation token of this process).
func maxAllowed(sd *windows.SECURITY_DESCRIPTOR) (uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		return 0, fmt.Errorf("access check: %w", err)
	}
	defer windows.RevertToSelf()
	thread, err := windows.GetCurrentThread()
	if err != nil {
		return 0, fmt.Errorf("access check: %w", err)
	}
	var tok windows.Token
	if err := windows.OpenThreadToken(thread, windows.TOKEN_QUERY, true, &tok); err != nil {
		return 0, fmt.Errorf("access check: %w", err)
	}
	defer tok.Close()
	// The file object's GENERIC_MAPPING (FILE_GENERIC_READ, _WRITE,
	// _EXECUTE and FILE_ALL_ACCESS).
	mapping := genericMapping{0x120089, 0x120116, 0x1200a0, 0x1f01ff}
	var privs [16]uint32 // a PRIVILEGE_SET with room to spare, aligned
	privLen := uint32(len(privs) * 4)
	var granted uint32
	var status int32
	r, _, e := procAccessCheck.Call(
		uintptr(unsafe.Pointer(sd)), uintptr(tok), maximumAllowed,
		uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privs[0])),
		uintptr(unsafe.Pointer(&privLen)), uintptr(unsafe.Pointer(&granted)),
		uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		return 0, fmt.Errorf("access check: %w", e)
	}
	if status == 0 {
		return 0, nil
	}
	return granted, nil
}
