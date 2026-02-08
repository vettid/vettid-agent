// Package fingerprint collects machine and binary identity attributes
// for platform binding and verification.
package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

const platformKeyLabel = "vettid-agent-platform-v1"

type MachineAttributes struct {
	Hostname  string `json:"hostname"`
	MachineID string `json:"machine_id"`
	CPU       string `json:"cpu"`
	DiskSerial string `json:"disk_serial"`
	MACAddress string `json:"mac_address"`
}

func CollectMachineAttributes() (*MachineAttributes, error) {
	attrs := &MachineAttributes{}

	hostname, err := os.Hostname()
	if err == nil {
		attrs.Hostname = hostname
	}

	switch runtime.GOOS {
	case "linux":
		attrs.MachineID = readFileContent("/etc/machine-id")
		attrs.CPU = collectLinuxCPU()
		attrs.DiskSerial = collectLinuxDiskSerial()
		attrs.MACAddress = collectLinuxMAC()
	case "darwin":
		attrs.MachineID = collectDarwinMachineID()
		attrs.CPU = collectDarwinCPU()
		attrs.DiskSerial = collectDarwinDiskSerial()
		attrs.MACAddress = collectDarwinMAC()
	default:
		// Windows and other platforms: stubs for now
	}

	return attrs, nil
}

func ComputeMachineFingerprint(attrs *MachineAttributes) []byte {
	parts := []string{
		"hostname:" + attrs.Hostname,
		"machine_id:" + attrs.MachineID,
		"cpu:" + attrs.CPU,
		"disk:" + attrs.DiskSerial,
		"mac:" + attrs.MACAddress,
	}
	sort.Strings(parts)

	data := strings.Join(parts, "\n")

	mac := hmac.New(sha256.New, []byte(platformKeyLabel))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func readFileContent(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Stub implementations — platform-specific collection is in machine_linux.go / machine_darwin.go
// These are fallbacks for unsupported or cross-compilation scenarios.

func collectLinuxCPU() string       { return "" }
func collectLinuxDiskSerial() string { return "" }
func collectLinuxMAC() string        { return "" }

func collectDarwinMachineID() string   { return "" }
func collectDarwinCPU() string         { return "" }
func collectDarwinDiskSerial() string  { return "" }
func collectDarwinMAC() string         { return "" }

func Platform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
