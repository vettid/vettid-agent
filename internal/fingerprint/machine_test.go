package fingerprint

import (
	"bytes"
	"testing"
)

func TestComputeMachineFingerprint_Deterministic(t *testing.T) {
	attrs := &MachineAttributes{
		Hostname:   "dev-server-01",
		MachineID:  "abc123def456",
		CPU:        "Intel Core i7-12700K",
		DiskSerial: "WD-12345",
		MACAddress: "aa:bb:cc:dd:ee:ff",
	}

	fp1 := ComputeMachineFingerprint(attrs)
	fp2 := ComputeMachineFingerprint(attrs)

	if !bytes.Equal(fp1, fp2) {
		t.Error("same attributes should produce same fingerprint")
	}

	if len(fp1) != 32 {
		t.Errorf("fingerprint length = %d, want 32 (SHA-256)", len(fp1))
	}
}

func TestComputeMachineFingerprint_DifferentAttributes(t *testing.T) {
	attrs1 := &MachineAttributes{
		Hostname:   "machine-A",
		MachineID:  "id-A",
		CPU:        "Intel",
		DiskSerial: "disk-A",
		MACAddress: "aa:aa:aa:aa:aa:aa",
	}

	attrs2 := &MachineAttributes{
		Hostname:   "machine-B",
		MachineID:  "id-B",
		CPU:        "Intel",
		DiskSerial: "disk-B",
		MACAddress: "bb:bb:bb:bb:bb:bb",
	}

	fp1 := ComputeMachineFingerprint(attrs1)
	fp2 := ComputeMachineFingerprint(attrs2)

	if bytes.Equal(fp1, fp2) {
		t.Error("different machines should produce different fingerprints")
	}
}

func TestComputeMachineFingerprint_SingleAttributeChange(t *testing.T) {
	base := &MachineAttributes{
		Hostname:   "dev-server",
		MachineID:  "abc123",
		CPU:        "Intel Core i7",
		DiskSerial: "WD-12345",
		MACAddress: "aa:bb:cc:dd:ee:ff",
	}

	modified := &MachineAttributes{
		Hostname:   "dev-server-renamed", // Only hostname changed
		MachineID:  "abc123",
		CPU:        "Intel Core i7",
		DiskSerial: "WD-12345",
		MACAddress: "aa:bb:cc:dd:ee:ff",
	}

	fpBase := ComputeMachineFingerprint(base)
	fpModified := ComputeMachineFingerprint(modified)

	if bytes.Equal(fpBase, fpModified) {
		t.Error("changing one attribute should change the fingerprint")
	}
}

func TestComputeMachineFingerprint_OrderIndependence(t *testing.T) {
	// The canonical format sorts keys, so field order in the struct shouldn't matter.
	// Verify by ensuring the sorted key order produces consistent results.
	attrs := &MachineAttributes{
		Hostname:   "test",
		MachineID:  "id",
		CPU:        "cpu",
		DiskSerial: "disk",
		MACAddress: "mac",
	}

	fp1 := ComputeMachineFingerprint(attrs)

	// The fields map keys would be: cpu, disk, hostname, mac, machine_id (sorted)
	// Creating a second identical attrs should produce the same result
	attrs2 := &MachineAttributes{
		MACAddress: "mac",
		DiskSerial: "disk",
		CPU:        "cpu",
		MachineID:  "id",
		Hostname:   "test",
	}

	fp2 := ComputeMachineFingerprint(attrs2)

	if !bytes.Equal(fp1, fp2) {
		t.Error("field order should not affect fingerprint")
	}
}

func TestComputeMachineFingerprintHex(t *testing.T) {
	attrs := &MachineAttributes{
		Hostname:  "test-host",
		MachineID: "test-id",
	}

	hex := ComputeMachineFingerprintHex(attrs)
	if len(hex) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("hex fingerprint length = %d, want 64", len(hex))
	}
}

func TestAttributeCount(t *testing.T) {
	tests := []struct {
		name  string
		attrs *MachineAttributes
		want  int
	}{
		{"all five", &MachineAttributes{"h", "m", "c", "d", "mac"}, 5},
		{"four", &MachineAttributes{"h", "m", "c", "", "mac"}, 4},
		{"three", &MachineAttributes{"h", "", "c", "", "mac"}, 3},
		{"one", &MachineAttributes{"h", "", "", "", ""}, 1},
		{"none", &MachineAttributes{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.attrs.AttributeCount()
			if got != tt.want {
				t.Errorf("AttributeCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFourOfFiveCombinations(t *testing.T) {
	attrs := &MachineAttributes{
		Hostname:   "host",
		MachineID:  "id",
		CPU:        "cpu",
		DiskSerial: "disk",
		MACAddress: "mac",
	}

	combos := FourOfFiveCombinations(attrs)
	if len(combos) != 5 {
		t.Fatalf("expected 5 combinations, got %d", len(combos))
	}

	// Each combo should have exactly 4 non-empty attributes
	for i, combo := range combos {
		count := combo.AttributeCount()
		if count != 4 {
			t.Errorf("combo %d has %d attributes, want 4", i, count)
		}
	}

	// Each combo should produce a different fingerprint
	fingerprints := make([][]byte, 5)
	for i, combo := range combos {
		fingerprints[i] = ComputeMachineFingerprint(combo)
	}

	for i := 0; i < len(fingerprints); i++ {
		for j := i + 1; j < len(fingerprints); j++ {
			if bytes.Equal(fingerprints[i], fingerprints[j]) {
				t.Errorf("combos %d and %d produced identical fingerprints", i, j)
			}
		}
	}

	// Verify which field was omitted in each combo
	if combos[0].Hostname != "" {
		t.Error("combo 0 should omit hostname")
	}
	if combos[1].MachineID != "" {
		t.Error("combo 1 should omit machine_id")
	}
	if combos[2].CPU != "" {
		t.Error("combo 2 should omit cpu")
	}
	if combos[3].DiskSerial != "" {
		t.Error("combo 3 should omit disk")
	}
	if combos[4].MACAddress != "" {
		t.Error("combo 4 should omit mac")
	}
}

func TestCollectMachineAttributes(t *testing.T) {
	attrs, err := CollectMachineAttributes()
	if err != nil {
		t.Fatalf("CollectMachineAttributes: %v", err)
	}

	// At minimum, hostname should be set on any system
	if attrs.Hostname == "" {
		t.Error("hostname should not be empty")
	}

	t.Logf("Collected attributes: hostname=%q machine_id=%q cpu=%q disk=%q mac=%q",
		attrs.Hostname, attrs.MachineID, attrs.CPU, attrs.DiskSerial, attrs.MACAddress)
	t.Logf("Attribute count: %d/5", attrs.AttributeCount())
}

func TestPlatform(t *testing.T) {
	p := Platform()
	if p == "" {
		t.Error("Platform() should not be empty")
	}
	// Should be in the form "os/arch"
	if len(p) < 3 {
		t.Errorf("Platform() = %q, seems too short", p)
	}
	t.Logf("Platform: %s", p)
}
