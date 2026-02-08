//go:build darwin

package fingerprint

import (
	"net"
	"os/exec"
	"strings"
)

func collectPlatformAttributes(attrs *MachineAttributes) {
	attrs.MachineID = collectDarwinMachineID()
	attrs.CPU = collectDarwinCPU()
	attrs.DiskSerial = collectDarwinDiskSerial()
	attrs.MACAddress = collectDarwinMAC()
}

// collectDarwinMachineID reads the IOPlatformUUID via ioreg.
func collectDarwinMachineID() string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				uuid := strings.TrimSpace(parts[1])
				uuid = strings.Trim(uuid, "\"")
				return uuid
			}
		}
	}
	return ""
}

// collectDarwinCPU reads the CPU brand string via sysctl.
func collectDarwinCPU() string {
	out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// collectDarwinDiskSerial reads the root disk serial via diskutil.
func collectDarwinDiskSerial() string {
	out, err := exec.Command("diskutil", "info", "/").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Disk / Partition UUID:") ||
			strings.HasPrefix(trimmed, "Volume UUID:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// collectDarwinMAC reads the en0 interface MAC address.
func collectDarwinMAC() string {
	iface, err := net.InterfaceByName("en0")
	if err != nil {
		return ""
	}
	if len(iface.HardwareAddr) == 0 {
		return ""
	}
	return iface.HardwareAddr.String()
}
