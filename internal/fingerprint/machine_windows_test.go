//go:build windows

package fingerprint

import (
	"regexp"
	"testing"
)

// Values are deliberately not logged: they identify the machine, and
// test output ends up in CI logs.

func TestCollectWindows_EnoughForPlatformKey(t *testing.T) {
	attrs, err := CollectMachineAttributes()
	if err != nil {
		t.Fatalf("CollectMachineAttributes: %v", err)
	}
	t.Logf("set: hostname=%v machine_id=%v cpu=%v disk=%v mac=%v",
		attrs.Hostname != "", attrs.MachineID != "", attrs.CPU != "",
		attrs.DiskSerial != "", attrs.MACAddress != "")

	// MachineGuid and the CPU brand come from the registry on every
	// Windows install, virtual machines included. Disk serial and MAC
	// can be absent in a VM.
	if attrs.MachineID == "" {
		t.Error("MachineGuid was not collected")
	}
	if attrs.CPU == "" {
		t.Error("CPU brand string was not collected")
	}
	if n := attrs.AttributeCount(); n < minAttributes {
		t.Errorf("collected %d attributes, need at least %d", n, minAttributes)
	}
	if _, err := DerivePlatformKey(""); err != nil {
		t.Errorf("DerivePlatformKey: %v", err)
	}
}

func TestCollectWindows_Deterministic(t *testing.T) {
	a, _ := CollectMachineAttributes()
	b, _ := CollectMachineAttributes()
	if *a != *b {
		t.Error("two collections on the same machine differ")
	}
}

func TestCollectWindows_Formats(t *testing.T) {
	attrs, _ := CollectMachineAttributes()

	guid := regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)
	if attrs.MachineID != "" && !guid.MatchString(attrs.MachineID) {
		t.Error("MachineGuid is not in GUID form")
	}
	mac := regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	if attrs.MACAddress != "" && !mac.MatchString(attrs.MACAddress) {
		t.Error("MAC address is not in aa:bb:cc:dd:ee:ff form")
	}
}

func TestFormatMAC(t *testing.T) {
	got := formatMAC([]byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0xFF})
	if want := "00:1a:2b:3c:4d:ff"; got != want {
		t.Errorf("formatMAC = %q, want %q", got, want)
	}
}

func TestQueryDiskSerial_MissingDeviceIsEmpty(t *testing.T) {
	if s := queryDiskSerial(`\\.\PhysicalDrive999`); s != "" {
		t.Error("a missing device returned a serial number")
	}
}
