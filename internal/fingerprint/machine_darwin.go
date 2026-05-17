//go:build darwin

package fingerprint

import (
	"net"
	"strings"
)

// SECURITY (#115): every exec.Command in this file goes through
// safeCommand which resolves the binary via exec.LookPath and refuses
// any path outside trustedExecDirs. Defeats $PATH-hijack attacks
// where a shadow `ioreg` / `sysctl` / `diskutil` planted in a
// user-writable directory would otherwise run.

func collectPlatformAttributes(attrs *MachineAttributes) {
	attrs.MachineID = collectDarwinMachineID()
	attrs.CPU = collectDarwinCPU()
	attrs.DiskSerial = collectDarwinDiskSerial()
	attrs.MACAddress = collectDarwinMAC()
}

// collectDarwinMachineID reads the IOPlatformUUID via ioreg.
func collectDarwinMachineID() string {
	cmd, err := safeCommand("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return ""
	}
	out, err := cmd.Output()
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
	cmd, err := safeCommand("sysctl", "-n", "machdep.cpu.brand_string")
	if err != nil {
		return ""
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// collectDarwinDiskSerial reads the root disk serial via diskutil.
func collectDarwinDiskSerial() string {
	cmd, err := safeCommand("diskutil", "info", "/")
	if err != nil {
		return ""
	}
	out, err := cmd.Output()
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
