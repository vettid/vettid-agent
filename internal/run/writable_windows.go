//go:build windows

package run

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
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
	if err := plainEntry(dir); err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("its access can't be read: %w", err)
	}
	return changes(sd, parent)
}

// plainEntry refuses a junction or other reparse point outright: links
// were resolved before this, but junctions aren't (Go 1.23+), and the
// security read of writable would describe its target, which its owner
// can change later. At the root it refuses a drive that is not a fixed
// local disk (fixedLocalDrive).
func plainEntry(dir string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return fmt.Errorf("is not a valid path")
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return fmt.Errorf("can't be checked: %w", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("is a junction, link or other reparse point (a OneDrive or deduplicated folder, for example); use a plain local directory")
	}
	if filepath.Dir(dir) == dir {
		if err := fixedLocalDrive(dir); err != nil {
			return err
		}
	}
	return nil
}

// plainPath applies plainEntry to a resolved program and every folder
// above it: the rules a pinned program still gets (ResolvePinned).
func plainPath(real string) error {
	for p := real; ; p = filepath.Dir(p) {
		if err := plainEntry(p); err != nil {
			return fmt.Errorf("%s %w", p, err)
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

// samePath compares two resolved paths exactly. Resolved paths carry the
// case the disk holds, so the same file gives the same string; a
// comparison without case would also equate characters Windows' own file
// names keep apart (EqualFold folds the Kelvin sign into k, for example).
func samePath(a, b string) bool { return a == b }

// changes reports whether the current user holds, over an object of sd, a
// right that changes it: any of dirRights, or for a folder above the
// checked ones (parent) any of parentRights.
func changes(sd *windows.SECURITY_DESCRIPTOR, parent bool) (bool, error) {
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

// fixedLocalDrive refuses a drive that is not a fixed local disk (a network,
// removable or optical drive, a RAM disk), and a drive letter mapped to a
// folder (subst, or DefineDosDevice in the user's own session), which its
// user can point elsewhere after the check. A standard user can't redefine
// an existing letter such as C: (Windows refuses it), only add new ones.
// (chosen; not in the spec)
func fixedLocalDrive(root string) error {
	p, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return fmt.Errorf("is not a valid path")
	}
	if t := windows.GetDriveType(p); t != windows.DRIVE_FIXED {
		return fmt.Errorf("is not on a fixed local drive; use a folder on a local disk")
	}
	vol := filepath.VolumeName(root)
	name, err := windows.UTF16PtrFromString(vol)
	if err != nil || len(vol) != 2 || vol[1] != ':' {
		return fmt.Errorf("is not on a plain drive letter (such as C:); use a folder on a local disk")
	}
	buf := make([]uint16, 1024)
	n, err := windows.QueryDosDevice(name, &buf[0], uint32(len(buf)))
	if err != nil {
		return fmt.Errorf("its drive can't be checked: %w", err)
	}
	// The first target is what the letter maps to: a device for a disk,
	// \??\<path> for a letter mapped to a folder.
	// A disk is \Device\<name> alone; a raw target with a path after
	// the device's name maps the letter to a folder just as subst does.
	target := windows.UTF16ToString(buf[:n])
	rest, ok := strings.CutPrefix(target, `\Device\`)
	if !ok || rest == "" || strings.Contains(rest, `\`) {
		return fmt.Errorf("is on a drive letter mapped to a folder (subst); use the folder's own path on a local disk")
	}
	return nil
}
