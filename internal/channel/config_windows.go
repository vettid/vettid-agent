//go:build windows

package channel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procAccessCheck = windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck")

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
// service's. The file must be one only an administrator can change: its
// owner Administrators or SYSTEM, and this process's user, with its
// groups, holding no right that changes it. A missing file, a file that
// fails the check, and a name that isn't n's are ErrNoService: the stub
// answers as when the service doesn't run. A changed name could only
// point the stub at a pipe that the owner check then refuses.
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
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !(owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) || owner.IsWellKnown(windows.WinLocalSystemSid)) {
		return "", noService("is not owned by Administrators or SYSTEM")
	}
	granted, err := maxAllowed(sd)
	if err != nil {
		return "", noService("can't be checked: %v", err)
	}
	if granted&configChangeRights != 0 {
		return "", noService("can be changed by this account (access %#x)", granted&configChangeRights)
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

// maxAllowed is what this process's user may do with an object of sd,
// the owner's implicit rights included (AccessCheck with
// MAXIMUM_ALLOWED and an impersonation token of this thread's user:
// the process's, or the one a test impersonates).
func maxAllowed(sd *windows.SECURITY_DESCRIPTOR) (uint32, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var tok windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok); err != nil {
		if !errors.Is(err, windows.ERROR_NO_TOKEN) {
			return 0, err
		}
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			return 0, err
		}
		defer windows.RevertToSelf()
		if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok); err != nil {
			return 0, err
		}
	}
	defer tok.Close()
	// The file object's GENERIC_MAPPING.
	mapping := [4]uint32{0x120089, 0x120116, 0x1200a0, 0x1f01ff}
	var privs [16]uint32
	privLen := uint32(len(privs) * 4)
	var granted uint32
	var status int32
	r, _, e := procAccessCheck.Call(
		uintptr(unsafe.Pointer(sd)), uintptr(tok), windows.MAXIMUM_ALLOWED,
		uintptr(unsafe.Pointer(&mapping)), uintptr(unsafe.Pointer(&privs[0])),
		uintptr(unsafe.Pointer(&privLen)), uintptr(unsafe.Pointer(&granted)),
		uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		return 0, e
	}
	if status == 0 {
		return 0, nil
	}
	return granted, nil
}
