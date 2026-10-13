//go:build windows

package fingerprint

import (
	"encoding/hex"
	"os"
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
// holds the system volume, falling back to the first physical disk.
// Both are opened with no access rights, which is enough for the
// query and works for a standard (non-administrator) user.
func collectWindowsDiskSerial() string {
	candidates := []string{`\\.\PhysicalDrive0`}
	if drive := os.Getenv("SystemDrive"); len(drive) == 2 && drive[1] == ':' {
		candidates = append([]string{`\\.\` + drive}, candidates...)
	}
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
	if err != nil || returned < serialNumberOffsetField+4 {
		return ""
	}
	buf = buf[:returned]

	offset := uint32(buf[serialNumberOffsetField]) |
		uint32(buf[serialNumberOffsetField+1])<<8 |
		uint32(buf[serialNumberOffsetField+2])<<16 |
		uint32(buf[serialNumberOffsetField+3])<<24
	// Zero means the device reports no serial number.
	if offset == 0 || offset >= uint32(len(buf)) {
		return ""
	}
	end := offset
	for end < uint32(len(buf)) && buf[end] != 0 {
		end++
	}
	return strings.TrimSpace(string(buf[offset:end]))
}

const (
	netAdapterClassKey = `SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}`
	// NCF_PHYSICAL: the adapter is a physical device, not a virtual one.
	ncfPhysical = 0x4
)

// physicalAdapterGUIDs returns the instance GUIDs (upper case, with
// braces) of the network adapters Windows marks as physical. Virtual
// switches, VPN adapters and the WSL and Hyper-V adapters are not
// marked, and they come and go, which would change the fingerprint.
func physicalAdapterGUIDs() map[string]bool {
	out := map[string]bool{}
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
		k.Close()
		if cErr != nil || gErr != nil || characteristics&ncfPhysical == 0 {
			continue
		}
		out[strings.ToUpper(guid)] = true
	}
	return out
}

// collectWindowsMAC returns the lowest MAC address among the physical
// Ethernet and Wi-Fi adapters, whether or not they are connected.
// Taking the lowest, not the first, keeps the result independent of
// the order Windows lists adapters in.
func collectWindowsMAC() string {
	physical := physicalAdapterGUIDs()
	if len(physical) == 0 {
		return ""
	}

	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER
	size := uint32(16 * 1024)
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0,
			(*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return ""
		}
		buf = nil
	}
	if buf == nil {
		return ""
	}

	var macs []string
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		if a.IfType != windows.IF_TYPE_ETHERNET_CSMACD && a.IfType != windows.IF_TYPE_IEEE80211 {
			continue
		}
		if a.PhysicalAddressLength != 6 {
			continue
		}
		if !physical[strings.ToUpper(windows.BytePtrToString(a.AdapterName))] {
			continue
		}
		mac := a.PhysicalAddress[:6]
		if isZero(mac) {
			continue
		}
		macs = append(macs, formatMAC(mac))
	}
	if len(macs) == 0 {
		return ""
	}
	sort.Strings(macs)
	return macs[0]
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
