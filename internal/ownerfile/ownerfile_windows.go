//go:build windows

package ownerfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// ownerOnlySD builds a security descriptor whose DACL is protected
// (inherits nothing from the parent) and grants full access to the
// current user alone. With inherit set, children created inside a
// directory get the same single entry.
func ownerOnlySD(inherit bool) (*windows.SECURITY_DESCRIPTOR, error) {
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
	return sd, nil
}

// restrict replaces the DACL of an open file with the owner-only one.
// It works on the handle, not the name, so it cannot be redirected to a
// different file between the open and the call.
func restrict(h windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL: %w", err)
	}
	err = windows.SetSecurityInfo(
		h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("set DACL: %w", err)
	}
	return nil
}

// WriteFile writes data to path so that only the current user can open
// it. A new file is created with the restricted DACL already in place,
// so there is no moment at which it carries the parent's inherited
// entries. An existing file keeps its old DACL through the truncate, so
// the DACL is replaced before any data is written.
func WriteFile(path string, data []byte) error {
	sd, err := ownerOnlySD(false)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_WRITE|windows.WRITE_DAC,
		0, // no sharing while we write
		sa,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)

	// SECURITY: CREATE_ALWAYS on an existing file ignores the security
	// attributes, so set the DACL explicitly before writing.
	if err := restrict(h, sd); err != nil {
		f.Close()
		return &os.PathError{Op: "restrict", Path: path, Err: err}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// MkdirAll creates dir and any missing parents. If dir itself did not
// exist it is created owner-only, and files later created inside it
// inherit that. An existing directory is left as it is, as on POSIX.
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
	sd, err := ownerOnlySD(true)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	if err := windows.CreateDirectory(p, sa); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	return nil
}

// Check returns an error if the DACL of path lets anyone other than the
// current user, SYSTEM or the Administrators group open it.
//
// SYSTEM and Administrators are tolerated because a file created the
// ordinary way under the user profile inherits entries for both, and
// because an administrator can take ownership of any file regardless
// of its DACL. This is the same rule OpenSSH for Windows applies to
// private keys.
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
