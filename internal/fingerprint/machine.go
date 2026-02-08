// Package fingerprint collects machine and binary identity attributes
// for platform binding and verification.
//
// The machine fingerprint binds encrypted credentials to a specific machine.
// Five attributes are collected: hostname, machine-id, CPU, disk serial, MAC address.
// The fingerprint is HMAC-SHA256 of these attributes with a fixed domain label.
//
// Platform-specific collection is in machine_linux.go and machine_darwin.go
// (selected by build tags). Unsupported platforms use machine_other.go.
package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
)

const platformKeyLabel = "vettid-agent-platform-v1"

// MachineAttributes holds the five identity attributes used for fingerprinting.
type MachineAttributes struct {
	Hostname   string `json:"hostname"`
	MachineID  string `json:"machine_id"`
	CPU        string `json:"cpu"`
	DiskSerial string `json:"disk_serial"`
	MACAddress string `json:"mac_address"`
}

// AttributeCount returns the number of non-empty attributes.
func (a *MachineAttributes) AttributeCount() int {
	count := 0
	if a.Hostname != "" {
		count++
	}
	if a.MachineID != "" {
		count++
	}
	if a.CPU != "" {
		count++
	}
	if a.DiskSerial != "" {
		count++
	}
	if a.MACAddress != "" {
		count++
	}
	return count
}

// Fields returns the attributes as a map for generating 4-of-5 combinations.
func (a *MachineAttributes) Fields() map[string]string {
	return map[string]string{
		"hostname":   a.Hostname,
		"machine_id": a.MachineID,
		"cpu":        a.CPU,
		"disk":       a.DiskSerial,
		"mac":        a.MACAddress,
	}
}

// CollectMachineAttributes gathers machine identity attributes using
// platform-specific collectors. The platform-specific functions are
// defined in machine_linux.go, machine_darwin.go, and machine_other.go.
func CollectMachineAttributes() (*MachineAttributes, error) {
	attrs := &MachineAttributes{}

	hostname, err := os.Hostname()
	if err == nil {
		attrs.Hostname = strings.TrimSpace(hostname)
	}

	// Platform-specific collection (dispatched via build tags)
	collectPlatformAttributes(attrs)

	return attrs, nil
}

// ComputeMachineFingerprint computes the HMAC-SHA256 fingerprint from machine attributes.
//
// The canonical format sorts key:value pairs alphabetically, joins with newlines,
// and computes HMAC-SHA256 with the fixed domain label as the key.
func ComputeMachineFingerprint(attrs *MachineAttributes) []byte {
	return computeFingerprintFromFields(attrs.Fields())
}

// ComputeMachineFingerprintHex returns the hex-encoded fingerprint string.
func ComputeMachineFingerprintHex(attrs *MachineAttributes) string {
	return hex.EncodeToString(ComputeMachineFingerprint(attrs))
}

// FourOfFiveCombinations generates all 5 possible 4-of-5 attribute combinations.
// Each combination omits one attribute (set to empty string).
// Used for tolerance: if the full fingerprint fails, try each 4-of-5 combo.
func FourOfFiveCombinations(attrs *MachineAttributes) []*MachineAttributes {
	fieldNames := []string{"hostname", "machine_id", "cpu", "disk", "mac"}
	fields := attrs.Fields()
	combos := make([]*MachineAttributes, 0, 5)

	for _, omit := range fieldNames {
		combo := &MachineAttributes{
			Hostname:   fields["hostname"],
			MachineID:  fields["machine_id"],
			CPU:        fields["cpu"],
			DiskSerial: fields["disk"],
			MACAddress: fields["mac"],
		}
		// Zero out the omitted field
		switch omit {
		case "hostname":
			combo.Hostname = ""
		case "machine_id":
			combo.MachineID = ""
		case "cpu":
			combo.CPU = ""
		case "disk":
			combo.DiskSerial = ""
		case "mac":
			combo.MACAddress = ""
		}
		combos = append(combos, combo)
	}

	return combos
}

func computeFingerprintFromFields(fields map[string]string) []byte {
	parts := make([]string, 0, len(fields))
	for k, v := range fields {
		parts = append(parts, k+":"+v)
	}
	sort.Strings(parts)

	data := strings.Join(parts, "\n")

	mac := hmac.New(sha256.New, []byte(platformKeyLabel))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// ReadFileContent reads a file and returns its trimmed content as a string.
// Returns empty string on any error.
func ReadFileContent(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// Platform returns the current OS/architecture string (e.g. "linux/amd64").
func Platform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
