//go:build !windows

package protect

// There is no DPAPI on this system: neither case applies.
func domainAccount() (bool, error)  { return false, nil }
func roamingProfile() (bool, error) { return false, nil }
