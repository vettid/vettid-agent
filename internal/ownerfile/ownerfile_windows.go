//go:build windows

package ownerfile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ACE flag: the entry applies to children only, not to the object itself.
const inheritOnlyACE = 0x08

// currentUserSID returns the SID of the user the process runs as.
func currentUserSID() (*windows.SID, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get token user: %w", err)
	}
	return tu.User.Sid, nil
}

// ownerOnlySA builds security attributes for a new object: owned by the
// current user, with a protected DACL (nothing inherited from the
// parent) that grants full access to that user alone. With inherit
// set, children created inside a directory get the same single entry.
func ownerOnlySA(inherit bool) (*windows.SecurityAttributes, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	flags := ""
	if inherit {
		flags = "OICI"
	}
	sddl := fmt.Sprintf("O:%sD:P(A;%s;FA;;;%s)", sid.String(), flags, sid.String())
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

// WriteFile writes data to path so that only the current user can open
// it.
//
// SECURITY: the data is never written into an object that already
// exists. An existing file keeps its owner and can keep handles that
// were opened before its DACL changed, and a symlink or hard link at
// the path would send the secret somewhere else. So the data goes to a
// new file beside the target, created owner-only from its first
// moment, and that file is then renamed over the target. The rename
// replaces whatever was at the path and carries the new file's owner
// and DACL with it. If any step fails the previous file is left as it
// was.
func WriteFile(path string, data []byte) error {
	sa, err := ownerOnlySA(false)
	if err != nil {
		return err
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("random temp name: %w", err)
	}
	tmp := filepath.Join(filepath.Dir(path),
		"."+filepath.Base(path)+"."+hex.EncodeToString(suffix[:])+".tmp")
	p, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	// CREATE_NEW fails if anything, a link included, is already there.
	// DELETE access is what lets the handle be renamed below.
	h, err := windows.CreateFile(
		p, windows.GENERIC_WRITE|windows.DELETE, 0, sa,
		windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0,
	)
	if err != nil {
		return &os.PathError{Op: "create", Path: tmp, Err: err}
	}
	f := os.NewFile(uintptr(h), tmp)

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}

	// Another process (antivirus, an indexer, tooling reading the
	// token) may hold the target open. A POSIX-style rename replaces
	// the target even then, provided the other process allowed
	// deletion; retry briefly for the ones that did not.
	for attempt := 0; ; attempt++ {
		err = renameOver(h, path)
		if err == nil || attempt == 4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return &os.PathError{Op: "replace", Path: path, Err: err}
	}
	return f.Close()
}

const (
	fileRenameInfoEx              = 22 // FILE_INFO_BY_HANDLE_CLASS
	fileRenameFlagReplaceIfExists = 0x1
	fileRenameFlagPosixSemantics  = 0x2
)

// fileRenameInfoHeader is FILE_RENAME_INFO up to, not including, the
// variable-length FileName that follows it.
type fileRenameInfoHeader struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32 // in bytes, without the terminating NUL
}

// renameOver renames the open file h to path, replacing a file that is
// already there. It asks for POSIX semantics first, which succeed even
// while the target is open elsewhere, and falls back to the classic
// replace on file systems that do not support them (FAT, some network
// shares). h must have been opened with DELETE access.
func renameOver(h windows.Handle, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(abs)
	if err != nil {
		return err
	}
	nameBytes := (len(name) - 1) * 2

	headerSize := int(unsafe.Offsetof(fileRenameInfoHeader{}.FileNameLength)) + 4
	buf := make([]byte, headerSize+len(name)*2)
	hdr := (*fileRenameInfoHeader)(unsafe.Pointer(&buf[0]))
	hdr.FileNameLength = uint32(nameBytes)
	copy(buf[headerSize:], unsafe.Slice((*byte)(unsafe.Pointer(&name[0])), len(name)*2))

	hdr.Flags = fileRenameFlagReplaceIfExists | fileRenameFlagPosixSemantics
	err = windows.SetFileInformationByHandle(h, fileRenameInfoEx, &buf[0], uint32(len(buf)))
	if err == nil {
		return nil
	}
	if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) && !errors.Is(err, windows.ERROR_NOT_SUPPORTED) &&
		!errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		return err
	}
	// FILE_RENAME_INFO: the same layout, where the first field is the
	// ReplaceIfExists boolean.
	hdr.Flags = 1
	return windows.SetFileInformationByHandle(h, windows.FileRenameInfo, &buf[0], uint32(len(buf)))
}

// MkdirAll creates dir and any missing parents. If dir itself did not
// exist it is created owner-only, and files later created inside it
// inherit that. Missing parents are created with the access they
// inherit. An existing directory is left as it is, as on POSIX.
func MkdirAll(dir string) error {
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return &os.PathError{Op: "mkdir", Path: dir, Err: errors.New("not a directory")}
		}
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return err
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
			// Something appeared between the Stat and the create. Accept
			// it only if it is a directory, as os.MkdirAll does.
			if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
				return nil
			}
		}
		return &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	return nil
}

// Check returns an error if path is owned by, or its DACL grants access
// to, anyone other than the current user, SYSTEM or the Administrators
// group.
//
// SYSTEM and Administrators are tolerated because a file created the
// ordinary way under the user profile inherits entries for both, and
// because an administrator can take ownership of any file regardless
// of its DACL. This is the same rule OpenSSH for Windows applies to
// private keys.
//
// It also rejects, by design, a file whose DACL names any other group:
// Users, Authenticated Users, a domain administrators group, and so
// on. To repair such a file:
//
//	icacls <path> /inheritance:r /grant:r "%USERNAME%:F"
func Check(path string) error {
	user, err := currentUserSID()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(user) || sid.Equals(system) || sid.Equals(admins)
	}

	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return &os.PathError{Op: "read security of", Path: path, Err: err}
	}

	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("has no readable owner")
	}
	if !trusted(owner) {
		return fmt.Errorf("is owned by %s, expected the current user", owner.String())
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("has no readable DACL: %w", err)
	}
	if dacl == nil {
		// SECURITY: a missing DACL grants everyone full access.
		return errors.New("has no DACL (open to everyone)")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read access entry %d: %w", i, err)
		}
		if ace.Header.AceFlags&inheritOnlyACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !trusted(sid) {
				return fmt.Errorf("grants access to %s, expected the current user only", sid.String())
			}
		default:
			// SECURITY: an entry type this code does not parse (object,
			// callback, ...) could grant access. Fail closed.
			return fmt.Errorf("has an access entry of unsupported type %d", ace.Header.AceType)
		}
	}
	return nil
}
