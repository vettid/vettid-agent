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
	a, errA := CollectMachineAttributes()
	b, errB := CollectMachineAttributes()
	if errA != nil || errB != nil {
		t.Fatalf("CollectMachineAttributes: %v / %v", errA, errB)
	}
	if *a != *b {
		t.Error("two collections on the same machine differ")
	}
}

func TestCollectWindows_Formats(t *testing.T) {
	attrs, err := CollectMachineAttributes()
	if err != nil {
		t.Fatalf("CollectMachineAttributes: %v", err)
	}

	guid := regexp.MustCompile(`^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$`)
	if !guid.MatchString(attrs.MachineID) {
		t.Error("MachineGuid is missing or not in GUID form")
	}
	if attrs.MACAddress == "" {
		t.Log("no MAC collected (expected on a machine with no physical adapter)")
	} else if !regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`).MatchString(attrs.MACAddress) {
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

// descriptor builds a STORAGE_DEVICE_DESCRIPTOR of the given size whose
// SerialNumberOffset field holds offset, with tail copied in at offset.
func descriptor(size int, offset uint32, tail []byte) []byte {
	d := make([]byte, size)
	if size >= serialNumberOffsetField+4 {
		d[serialNumberOffsetField] = byte(offset)
		d[serialNumberOffsetField+1] = byte(offset >> 8)
		d[serialNumberOffsetField+2] = byte(offset >> 16)
		d[serialNumberOffsetField+3] = byte(offset >> 24)
	}
	if int(offset) < size {
		copy(d[offset:], tail)
	}
	return d
}

func TestParseDiskSerial(t *testing.T) {
	cases := []struct {
		name string
		desc []byte
		want string
	}{
		{"plain", descriptor(64, 40, []byte("WD-ABC123\x00")), "WD-ABC123"},
		{"padded", descriptor(64, 40, []byte("   S4EWNX0N  \x00")), "S4EWNX0N"},
		{"nvme eui-64", descriptor(64, 40, []byte("0025_3885_91B1_23A4.\x00")), "0025_3885_91B1_23A4."},
		{"no serial (offset 0)", descriptor(64, 0, nil), ""},
		{"offset past the end", descriptor(64, 64, nil), ""},
		{"offset far past the end", descriptor(64, 0xFFFFFFFF, nil), ""},
		{"not terminated", descriptor(48, 40, []byte("ABCDEFGH")), ""},
		{"empty string", descriptor(64, 40, []byte("\x00")), ""},
		{"only spaces", descriptor(64, 40, []byte("    \x00")), ""},
		{"placeholder zeros", descriptor(64, 40, []byte("0000_0000_0000_0000.\x00")), ""},
		{"placeholder plain zeros", descriptor(64, 40, []byte("00000000\x00")), ""},
		{"too short for the field", make([]byte, serialNumberOffsetField+3), ""},
		{"empty", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseDiskSerial(c.desc); got != c.want {
				t.Errorf("parseDiskSerial = %q, want %q", got, c.want)
			}
		})
	}
}

func TestChooseMAC(t *testing.T) {
	cases := []struct {
		name string
		in   []macCandidate
		want string
	}{
		{"none", nil, ""},
		{"one built-in", []macCandidate{{"aa:00:00:00:00:02", true}}, "aa:00:00:00:00:02"},
		{"lowest built-in, any order", []macCandidate{
			{"aa:00:00:00:00:09", true}, {"aa:00:00:00:00:02", true},
		}, "aa:00:00:00:00:02"},
		{"a dock with a lower address does not win", []macCandidate{
			{"aa:00:00:00:00:09", true}, {"00:00:00:00:00:01", false},
		}, "aa:00:00:00:00:09"},
		{"only removable adapters: lowest of them", []macCandidate{
			{"cc:00:00:00:00:05", false}, {"bb:00:00:00:00:05", false},
		}, "bb:00:00:00:00:05"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := chooseMAC(c.in); got != c.want {
				t.Errorf("chooseMAC = %q, want %q", got, c.want)
			}
		})
	}
}
