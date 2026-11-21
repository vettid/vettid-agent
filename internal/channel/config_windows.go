//go:build windows

package channel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxConfig bounds the configuration file.
const maxConfig = 64 << 10

// configChangeRights are the rights over the configuration file that
// would let their holder change it.
const configChangeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA |
	windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER

// ConfigPath is pairing n's configuration file,
// %ProgramData%\VettID\agent\<n>.json. The folder comes from Windows'
// known folders, never from the ProgramData variable, which the agent
// could set in its own MCP configuration.
func ConfigPath(n string) (string, error) {
	if !ValidName(n) {
		return "", fmt.Errorf("%q is not a pairing's name: use 1 to 32 lowercase letters, digits or hyphens, starting with a letter or digit", n)
	}
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", fmt.Errorf("the ProgramData folder: %w", err)
	}
	return filepath.Join(pd, "VettID", "agent", n+".json"), nil
}

// ReadPipe returns pairing n's pipe name from its configuration file.
// The stub reads only the name: the pairing's other settings are the
// service's. The file must be one only an administrator can change
// (adminOnly), judged by its own security descriptor, whoever reads it:
// the member, or an elevated administrator running pair or forget. A
// missing file, a file that fails the check, and a name that isn't n's
// are ErrNoService: the stub answers as when the service doesn't run.
//
// Only the file is checked, not the folders above it. A member who made
// %ProgramData%\VettID before the install, or a junction there, could
// put another file in its place, but not one owned by Administrators or
// SYSTEM, which this refuses; and a name that leads elsewhere only
// reaches a pipe that Dial's owner check refuses. Either way the cost is
// a denial of service, not a disclosure. The installer makes the folders
// with an access list of their own (A5.5).
func ReadPipe(n string) (string, error) {
	path, err := ConfigPath(n)
	if err != nil {
		return "", err
	}
	return readPipeAt(path, n)
}

func readPipeAt(path, n string) (string, error) {
	noService := func(why string, a ...any) error {
		return fmt.Errorf("%w: %s %s", ErrNoService, path, fmt.Sprintf(why, a...))
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", noService("is not a valid path")
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return "", noService("does not exist")
		}
		return "", noService("can't be opened: %v", err)
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", noService("can't be read: %v", err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return "", noService("is a link or a folder")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", noService("its access can't be read: %v", err)
	}
	if err := adminOnly(sd); err != nil {
		return "", noService("%v", err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil {
		return "", noService("can't be read: %v", err)
	}
	if len(b) > maxConfig {
		return "", noService("is too large")
	}
	var c struct {
		Pipe string `json:"pipe"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return "", noService("is not valid JSON")
	}
	if !validPipe(n, c.Pipe) {
		return "", noService("does not name this pairing's channel")
	}
	return c.Pipe, nil
}

// trustedInstaller is NT SERVICE\TrustedInstaller.
var trustedInstaller = ServiceSID("TrustedInstaller")

// adminOnly reports whether an object of sd can be changed only by an
// administrator: its owner is Administrators or SYSTEM, its access list
// is present, and no entry that applies to the object itself allows a
// right that changes it (configChangeRights, or GENERIC_WRITE or
// GENERIC_ALL) to anyone but Administrators, SYSTEM or TrustedInstaller.
// Deny entries can only take rights away; an entry of a type this check
// doesn't know refuses the file. It reads the descriptor only, not any
// token, so it gives the same answer to the member and to an elevated
// administrator.
func adminOnly(sd *windows.SECURITY_DESCRIPTOR) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !(owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return errors.New("is not owned by Administrators or SYSTEM")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("has no access list (anyone may change it)")
	}
	const change = configChangeRights | windows.GENERIC_WRITE | windows.GENERIC_ALL
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("its access list can't be read: %v", err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("has an access entry of type %d, which this check doesn't know", ace.Header.AceType)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&change == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.String() == trustedInstaller {
			continue
		}
		return fmt.Errorf("can be changed by %s (access %#x)", sid, uint32(ace.Mask)&change)
	}
	return nil
}
