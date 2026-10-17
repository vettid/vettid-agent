//go:build windows

package state

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows owner-only files: the state directory, the state file, its
// temporary files and the lock file are created owned by the current
// user with a protected DACL (nothing inherited from the parent) that
// holds one entry, full access for the current user. On load, the owner
// must be the current user and no access-allowed entry may name anyone
// else; a missing DACL (open to everyone) or an entry type this code
// does not parse is refused.
//
// SYSTEM and the Administrators group are not accepted either (chosen):
// the connector creates the directory itself, so its entries are only
// the current user's. An existing directory made another way usually
// inherits entries for both and is refused; to tighten it:
//
//	icacls <dir> /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"

// currentUserSID returns the SID of the user the process runs as.
func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("state: read the current user: %w", err)
	}
	return tu.User.Sid, nil
}

// ownerOnlySA returns security attributes for a new object owned by the
// current user with a protected DACL granting that user full access.
// With inherit set (a directory), files and directories created inside
// it get the same single entry.
func ownerOnlySA(inherit bool) (*windows.SecurityAttributes, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	s := sid.String()
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P(A;%s;FA;;;%s)", s, flags, s))
	if err != nil {
		return nil, fmt.Errorf("state: build security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

func mkdirOwnerOnly(dir string) error {
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 {
			return notPrivate("state directory", "is a link")
		}
		if !fi.IsDir() {
			return fmt.Errorf("state: %s is not a directory", dir)
		}
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return fmt.Errorf("state: create parent directory: %w", err)
		}
	}
	sa, err := ownerOnlySA(true)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil // created meanwhile; checkDir decides
		}
		return fmt.Errorf("state: create state directory: %w", err)
	}
	return nil
}

// checkSecurity applies the owner-only rule to a security descriptor.
func checkSecurity(what string, sd *windows.SECURITY_DESCRIPTOR) error {
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return notPrivate(what, "has no readable owner")
	}
	if !owner.Equals(user) {
		return notPrivate(what, "is owned by "+owner.String()+", not the current user")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return notPrivate(what, "has no readable access list")
	}
	if dacl == nil {
		// A missing DACL grants everyone full access.
		return notPrivate(what, "has no access list (open to everyone)")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return notPrivate(what, fmt.Sprintf("access entry %d is unreadable", i))
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			// Inherit-only entries are checked too: they would apply to
			// files created inside a directory.
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !sid.Equals(user) {
				return notPrivate(what, "grants access to "+sid.String())
			}
		default:
			// Object, callback and other entry types can grant access
			// and are not parsed here: fail closed.
			return notPrivate(what, fmt.Sprintf("has an access entry of unsupported type %d", ace.Header.AceType))
		}
	}
	return nil
}

func checkDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("state: state directory: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeIrregular != 0 {
		return notPrivate("state directory", "is a link")
	}
	if !fi.IsDir() {
		return fmt.Errorf("state: %s is not a directory", dir)
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return notPrivate("state directory", "security is unreadable")
	}
	return checkSecurity("state directory", sd)
}

func checkFile(f *os.File) error {
	h := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("state: state file: %w", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return notPrivate("state file", "is not a regular file")
	}
	if info.NumberOfLinks != 1 {
		return notPrivate("state file", "has more than one link")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return notPrivate("state file", "security is unreadable")
	}
	return checkSecurity("state file", sd)
}

// openNoFollow opens path with FILE_FLAG_OPEN_REPARSE_POINT, so that a
// symbolic link or junction at the path is opened itself, not followed.
// It returns errNotRegular for a reparse point or a directory.
func openNoFollow(path string, access uint32) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		f.Close()
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		f.Close()
		return nil, errNotRegular
	}
	return f, nil
}

func openPrivate(path string) (*os.File, error) {
	f, err := openNoFollow(path, windows.GENERIC_READ|windows.READ_CONTROL)
	if errors.Is(err, errNotRegular) {
		return nil, notPrivate("state file", "is a link or not a regular file")
	}
	return f, err
}

func openForOverwrite(path string) (*os.File, error) {
	return openNoFollow(path, windows.GENERIC_WRITE)
}

func createTemp(dir, prefix, suffix string) (*os.File, string, error) {
	var r [16]byte
	if _, err := rand.Read(r[:]); err != nil {
		return nil, "", err
	}
	name := filepath.Join(dir, prefix+hex.EncodeToString(r[:])+suffix)
	sa, err := ownerOnlySA(false)
	if err != nil {
		return nil, "", err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, "", err
	}
	// CREATE_NEW refuses anything already at the name, a link included.
	h, err := windows.CreateFile(p, windows.GENERIC_WRITE, 0, sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, "", &os.PathError{Op: "create", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), name, nil
}

// renameReplace renames from over to. It asks for POSIX semantics
// first (SetFileInformationByHandle with FileRenameInfoEx and
// FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS), which
// replace the target even while a handle to it is open with delete
// sharing: CreateReplace holds the old state file open across the
// rename so that it can overwrite it afterwards. Where the file system
// does not support that (FAT, some network shares) it falls back to
// MoveFileEx(REPLACE_EXISTING | WRITE_THROUGH). A target held open
// without delete sharing makes either fail; that is retried for about
// 200 ms.
func renameReplace(from, to string) error {
	var err error
	for attempt := 0; ; attempt++ {
		err = renamePOSIX(from, to)
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
			errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
			err = moveFileEx(from, to)
		}
		if err == nil || attempt == 4 ||
			!(errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func moveFileEx(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(f, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// fileRenameInfoHeader is FILE_RENAME_INFO up to, not including, the
// variable-length FileName that follows it.
type fileRenameInfoHeader struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32 // in bytes, without the terminating NUL
}

func renamePOSIX(from, to string) error {
	p, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	abs, err := filepath.Abs(to)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(abs)
	if err != nil {
		return err
	}
	headerSize := int(unsafe.Offsetof(fileRenameInfoHeader{}.FileNameLength)) + 4
	buf := make([]byte, headerSize+len(name)*2)
	hdr := (*fileRenameInfoHeader)(unsafe.Pointer(&buf[0]))
	hdr.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	hdr.FileNameLength = uint32((len(name) - 1) * 2)
	copy(buf[headerSize:], unsafe.Slice((*byte)(unsafe.Pointer(&name[0])), len(name)*2))
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfoEx, &buf[0], uint32(len(buf)))
}

// syncDir is a no-op on Windows: a directory handle cannot be flushed.
// The file's data is flushed before the rename; the rename itself is
// journaled by NTFS (and written through on the MoveFileEx fallback).
func syncDir(string) error { return nil }

type winLock struct{ h windows.Handle }

func (l *winLock) Close() error {
	ol := new(windows.Overlapped)
	windows.UnlockFileEx(l.h, 0, 1, 0, ol)
	return windows.CloseHandle(l.h)
}

// lockDir takes an exclusive LockFileEx lock on the lock file, without
// waiting. The lock lasts until the returned Closer is closed or the
// process exits; the lock file itself stays.
func lockDir(path string) (io.Closer, error) {
	sa, err := ownerOnlySA(false)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, ErrInUse
		}
		return nil, fmt.Errorf("state: open lock file: %w", err)
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		windows.CloseHandle(h)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, ErrInUse
		}
		return nil, fmt.Errorf("state: lock: %w", err)
	}
	return &winLock{h: h}, nil
}
