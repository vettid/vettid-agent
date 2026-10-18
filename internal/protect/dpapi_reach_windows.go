//go:build windows

package protect

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// tokenSID returns the current process's user SID.
func tokenSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("token user: %w", err)
	}
	return u.User.Sid, nil
}

// domainAccount reports whether the current user is a domain account:
// the computer is joined to an Active Directory domain
// (NetGetJoinInformation) and the user's account domain is not the
// computer itself (a local account's domain is the computer name;
// built-in accounts such as SYSTEM are not user accounts). A computer
// joined to Microsoft Entra ID only is not an Active Directory domain
// member and gives no notice.
func domainAccount() (bool, error) {
	var name *uint16
	var joinType uint32
	if err := windows.NetGetJoinInformation(nil, &name, &joinType); err != nil {
		return false, fmt.Errorf("NetGetJoinInformation: %w", err)
	}
	windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	if joinType != windows.NetSetupDomainName {
		return false, nil
	}
	sid, err := tokenSID()
	if err != nil {
		return false, err
	}
	_, domain, accType, err := sid.LookupAccount("")
	if err != nil {
		return false, fmt.Errorf("account lookup: %w", err)
	}
	if accType != windows.SidTypeUser {
		return false, nil
	}
	computer, err := windows.ComputerName()
	if err != nil {
		return false, fmt.Errorf("computer name: %w", err)
	}
	return !strings.EqualFold(domain, computer), nil
}

// GetProfileType's flags (userenv.h).
const (
	ptRoaming            = 0x2
	ptRoamingPreexisting = 0x8
)

var procGetProfileType = windows.NewLazySystemDLL("userenv.dll").NewProc("GetProfileType")

// roamingProfile reports whether the current user has a roaming profile:
// GetProfileType says the loaded profile is roaming, or the user's
// ProfileList entry names a central (server) profile, which also covers
// a roaming profile that is configured but was loaded from the local
// copy this time. It fails only when both checks fail.
func roamingProfile() (bool, error) {
	byType, typeErr := profileTypeRoaming()
	if byType {
		return true, nil
	}
	byList, listErr := centralProfileSet()
	if byList {
		return true, nil
	}
	if typeErr != nil && listErr != nil {
		return false, errors.Join(typeErr, listErr)
	}
	return false, nil
}

func profileTypeRoaming() (bool, error) {
	if err := procGetProfileType.Find(); err != nil {
		return false, fmt.Errorf("GetProfileType: %w", err)
	}
	var flags uint32
	r, _, e := procGetProfileType.Call(uintptr(unsafe.Pointer(&flags)))
	if r == 0 {
		return false, fmt.Errorf("GetProfileType: %w", e)
	}
	return flags&(ptRoaming|ptRoamingPreexisting) != 0, nil
}

func centralProfileSet() (bool, error) {
	sid, err := tokenSID()
	if err != nil {
		return false, err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`+sid.String(), registry.QUERY_VALUE)
	if err != nil {
		return false, fmt.Errorf("ProfileList entry: %w", err)
	}
	defer k.Close()
	v, _, err := k.GetStringValue("CentralProfile")
	if errors.Is(err, registry.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("CentralProfile: %w", err)
	}
	return strings.TrimSpace(v) != "", nil
}
