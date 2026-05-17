//go:build linux

package fingerprint

import (
	"bufio"
	"net"
	"os"
	"strings"
)

func collectPlatformAttributes(attrs *MachineAttributes) {
	attrs.MachineID = ReadFileContent("/etc/machine-id")
	attrs.CPU = collectLinuxCPU()
	attrs.DiskSerial = collectLinuxDiskSerial()
	attrs.MACAddress = collectLinuxMAC()
}

// collectLinuxCPU reads the CPU model from /proc/cpuinfo.
// Uses "model name" which includes brand string and stepping.
func collectLinuxCPU() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// collectLinuxDiskSerial reads the root disk serial using lsblk.
//
// SECURITY (#115): every exec.Command goes through safeCommand which
// resolves the binary via exec.LookPath and refuses any path outside
// the trusted system dirs — defeats $PATH-hijack attacks where a
// shadow `lsblk` planted in a user-writable directory would otherwise
// run.
func collectLinuxDiskSerial() string {
	run := func(args ...string) ([]byte, error) {
		cmd, err := safeCommand("lsblk", args...)
		if err != nil {
			return nil, err
		}
		return cmd.Output()
	}

	// Try lsblk first (most reliable)
	out, err := run("--nodeps", "-o", "SERIAL", "-n", "/dev/sda")
	if err == nil {
		serial := strings.TrimSpace(string(out))
		if serial != "" {
			return serial
		}
	}

	// Fallback: try nvme0n1 (common on modern systems)
	out, err = run("--nodeps", "-o", "SERIAL", "-n", "/dev/nvme0n1")
	if err == nil {
		serial := strings.TrimSpace(string(out))
		if serial != "" {
			return serial
		}
	}

	// Fallback: try to find the root disk
	out, err = run("--nodeps", "-o", "NAME,SERIAL", "-n")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "" {
				return fields[1]
			}
		}
	}

	return ""
}

// collectLinuxMAC reads the first non-loopback network interface MAC address.
func collectLinuxMAC() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		// Skip loopback, virtual, and down interfaces
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 {
			continue
		}

		// Skip common virtual interface prefixes
		name := iface.Name
		if strings.HasPrefix(name, "veth") ||
			strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "virbr") ||
			strings.HasPrefix(name, "vnet") {
			continue
		}

		return iface.HardwareAddr.String()
	}

	return ""
}
