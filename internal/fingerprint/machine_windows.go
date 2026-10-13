//go:build windows

package fingerprint

import (
	"encoding/hex"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SECURITY: every attribute is read through the registry or a Win32
// call, never by running a helper program. The Linux and macOS
// collectors shell out to lsblk / ioreg and have to pin the binary's
// directory (exec_safe.go); on Windows there is no helper to shadow.
//
// The exact text of each value is part of the platform key. Changing
// how a value is chosen or formatted changes the key of every Windows
// install, so treat the rules in this file as a wire format.

func collectPlatformAttributes(attrs *MachineAttributes) {
	attrs.MachineID = collectWindowsMachineGUID()
	attrs.CPU = collectWindowsCPU()
	attrs.DiskSerial = collectWindowsDiskSerial()
	attrs.MACAddress = collectWindowsMAC()
}

// readHKLMString reads one string value from the 64-bit view of
// HKEY_LOCAL_MACHINE. The explicit view matters for a 32-bit build,
// which would otherwise be redirected to WOW6432Node.
func readHKLMString(path, name string) string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// collectWindowsMachineGUID reads MachineGuid, which Windows setup
// generates once per installation. It is the counterpart of
// /etc/machine-id: stable across reboots and updates, new after a
// reinstall, and shared by machines cloned from one image that was not
// generalised with sysprep.
func collectWindowsMachineGUID() string {
	return readHKLMString(`SOFTWARE\Microsoft\Cryptography`, "MachineGuid")
}

// collectWindowsCPU reads the brand string of the first processor,
// the same text /proc/cpuinfo reports as "model name".
func collectWindowsCPU() string {
	return readHKLMString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`, "ProcessorNameString")
}

const (
	ioctlStorageQueryProperty = 0x002D1400
	// Byte offset of SerialNumberOffset in STORAGE_DEVICE_DESCRIPTOR.
	serialNumberOffsetField = 24
)

// storagePropertyQuery is STORAGE_PROPERTY_QUERY with PropertyId
// StorageDeviceProperty (0) and QueryType PropertyStandardQuery (0).
type storagePropertyQuery struct {
	PropertyID           uint32
	QueryType            uint32
	AdditionalParameters [1]byte
}

// collectWindowsDiskSerial returns the serial number of the disk that
// holds the Windows volume, falling back to the first physical disk.
// Both are opened with no access rights, which is enough for the
// query and works for a standard (non-administrator) user.
//
// The string is whatever the storage driver reports. The inbox NVMe
// driver gives the drive's EUI-64 ("0025_3885_91B1_23A4."), not the
// serial printed on the label, and a vendor driver may give a
// different string for the same drive.
func collectWindowsDiskSerial() string {
	var candidates []string
	// From the OS, not %SystemDrive%, which the environment can change.
	if dir, err := windows.GetSystemWindowsDirectory(); err == nil && len(dir) >= 2 && dir[1] == ':' {
		candidates = append(candidates, `\\.\`+dir[:2])
	}
	candidates = append(candidates, `\\.\PhysicalDrive0`)
	for _, device := range candidates {
		if serial := queryDiskSerial(device); serial != "" {
			return serial
		}
	}
	return ""
}

func queryDiskSerial(device string) string {
	p, err := windows.UTF16PtrFromString(device)
	if err != nil {
		return ""
	}
	h, err := windows.CreateFile(
		p, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, 0, 0,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	query := storagePropertyQuery{}
	buf := make([]byte, 1024)
	var returned uint32
	err = windows.DeviceIoControl(
		h, ioctlStorageQueryProperty,
		(*byte)(unsafe.Pointer(&query)), uint32(unsafe.Sizeof(query)),
		&buf[0], uint32(len(buf)),
		&returned, nil,
	)
	if err != nil || returned > uint32(len(buf)) {
		return ""
	}
	return parseDiskSerial(buf[:returned])
}

// parseDiskSerial extracts the serial number from a
// STORAGE_DEVICE_DESCRIPTOR. It returns "" when the device reports
// none, when the descriptor is truncated, or when the serial is a
// placeholder.
func parseDiskSerial(desc []byte) string {
	if len(desc) < serialNumberOffsetField+4 {
		return ""
	}
	offset := uint32(desc[serialNumberOffsetField]) |
		uint32(desc[serialNumberOffsetField+1])<<8 |
		uint32(desc[serialNumberOffsetField+2])<<16 |
		uint32(desc[serialNumberOffsetField+3])<<24
	// Zero means the device reports no serial number.
	if offset == 0 || offset >= uint32(len(desc)) {
		return ""
	}
	end := offset
	for end < uint32(len(desc)) && desc[end] != 0 {
		end++
	}
	if end == uint32(len(desc)) {
		// No terminator: the string was cut off.
		return ""
	}
	serial := strings.TrimSpace(string(desc[offset:end]))
	if isPlaceholderSerial(serial) {
		return ""
	}
	return serial
}

// isPlaceholderSerial reports whether a serial carries no identity:
// only zeros and separators, which is what a drive without an EUI-64
// reports ("0000_0000_0000_0000.") and many units share.
func isPlaceholderSerial(serial string) bool {
	for _, r := range serial {
		switch r {
		case '0', '_', '.', '-', ' ':
		default:
			return false
		}
	}
	return true
}

const (
	netAdapterClassKey = `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`
	// NCF_PHYSICAL: the adapter is a physical device, not a virtual one.
	ncfPhysical = 0x4
)

// physicalAdapter is one adapter the registry marks as physical.
type physicalAdapter struct {
	// builtIn is true for an adapter on the PCI bus: soldered or in an
	// internal slot, as opposed to a USB or dock adapter.
	builtIn bool
}

// physicalAdapters returns the adapters Windows marks as physical,
// keyed by instance GUID (upper case, with braces). Virtual switches,
// VPN adapters and the WSL and Hyper-V adapters are not marked, and
// they come and go, which would change the fingerprint.
func physicalAdapters() map[string]physicalAdapter {
	out := map[string]physicalAdapter{}
	class, err := registry.OpenKey(registry.LOCAL_MACHINE, netAdapterClassKey,
		registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return out
	}
	defer class.Close()
	names, err := class.ReadSubKeyNames(-1)
	if err != nil {
		return out
	}
	for _, name := range names {
		k, err := registry.OpenKey(class, name, registry.QUERY_VALUE)
		if err != nil {
			// "Properties" and similar subkeys are not readable; skip.
			continue
		}
		characteristics, _, cErr := k.GetIntegerValue("Characteristics")
		guid, _, gErr := k.GetStringValue("NetCfgInstanceId")
		instance, _, _ := k.GetStringValue("DeviceInstanceID")
		k.Close()
		if cErr != nil || gErr != nil || characteristics&ncfPhysical == 0 {
			continue
		}
		out[strings.ToUpper(guid)] = physicalAdapter{
			builtIn: strings.HasPrefix(strings.ToUpper(instance), `PCI\`),
		}
	}
	return out
}

// macCandidate is one adapter considered for the MAC attribute.
type macCandidate struct {
	mac     string
	builtIn bool
}

// collectWindowsMAC returns the MAC attribute: see chooseMAC for the
// rule. It reads each adapter's permanent (burned-in) address, not the
// one in use, so Windows' "random hardware addresses" setting and a
// manual override do not change it.
func collectWindowsMAC() string {
	physical := physicalAdapters()
	if len(physical) == 0 {
		return ""
	}

	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 * 1024)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW || size == 0 || size > 16*1024*1024 {
			return ""
		}
	}

	var candidates []macCandidate
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.IfType != windows.IF_TYPE_ETHERNET_CSMACD && a.IfType != windows.IF_TYPE_IEEE80211 {
			continue
		}
		adapter, ok := physical[strings.ToUpper(windows.BytePtrToString(a.AdapterName))]
		if !ok {
			continue
		}
		row := windows.MibIfRow2{InterfaceLuid: a.Luid}
		if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormalWithoutStatistics, &row); err != nil {
			continue
		}
		if row.PhysicalAddressLength != 6 {
			continue
		}
		mac := row.PermanentPhysicalAddress[:6]
		if isZero(mac) {
			continue
		}
		candidates = append(candidates, macCandidate{mac: formatMAC(mac), builtIn: adapter.builtIn})
	}
	return chooseMAC(candidates)
}

// chooseMAC picks the MAC attribute from the physical adapters: the
// lowest address among the built-in ones, or, if there is none, the
// lowest among the rest.
//
// Built-in adapters are preferred so that plugging in a dock or a USB
// Ethernet adapter does not change the result. Taking the lowest, not
// the first, keeps it independent of the order Windows lists adapters
// in.
func chooseMAC(candidates []macCandidate) string {
	var builtIn, other []string
	for _, c := range candidates {
		if c.builtIn {
			builtIn = append(builtIn, c.mac)
		} else {
			other = append(other, c.mac)
		}
	}
	pick := builtIn
	if len(pick) == 0 {
		pick = other
	}
	if len(pick) == 0 {
		return ""
	}
	sort.Strings(pick)
	return pick[0]
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// formatMAC renders aa:bb:cc:dd:ee:ff, the form net.HardwareAddr uses
// on the other platforms.
func formatMAC(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = hex.EncodeToString([]byte{v})
	}
	return strings.Join(parts, ":")
}
