//go:build linux

package protect

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// realTPMEnv enables the test against this computer's TPM. The tests
// never touch /dev/tpmrm0 without it.
const realTPMEnv = "VETTID_AGENT_TEST_REAL_TPM"

func TestTPMName(t *testing.T) {
	if NewTPM(DefaultTPMDevice).Name() != "tpm" {
		t.Fatal("Name")
	}
	if NewTPM(DefaultTPMDevice).Wipe() != nil {
		t.Fatal("Wipe")
	}
}

// testSRKName is a well-formed SHA-256 Name.
var testSRKName = append([]byte{0x00, 0x0b}, make([]byte, 32)...)

// Blobs that are not this protector's format are refused before the
// TPM is opened.
func TestTPMBlobFormatRefused(t *testing.T) {
	opened := false
	p := &TPM{device: "test", open: func() (transport.TPMCloser, error) {
		opened = true
		return nil, errors.New("must not be opened")
	}}
	// A well-formed blob whose sealed object has other attributes
	// (FixedTPM off: it could be duplicated to another TPM).
	loose := sealTemplate
	loose.ObjectAttributes.FixedTPM = false
	pubLoose := tpm2.Marshal(tpm2.New2B(loose))
	pubGood := tpm2.Marshal(tpm2.New2B(sealTemplate))
	priv := tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: []byte{1, 2, 3, 4}})
	good := encodeTPMBlob(testSRKName, pubGood, priv)
	v1 := append([]byte{1}, good[1:]...)
	cases := map[string][]byte{
		"empty":                    nil,
		"version 1":                v1,
		"version 3":                append([]byte{3}, good[1:]...),
		"truncated":                good[:len(good)-1],
		"trailing":                 append(append([]byte{}, good...), 0),
		"zero length":              {2, 0, 0, 0, 0, 0, 0},
		"public garbage":           encodeTPMBlob(testSRKName, []byte{0, 1, 0xaa}, priv),
		"SRK name length":          encodeTPMBlob(testSRKName[:20], pubGood, priv),
		"SRK name algorithm":       encodeTPMBlob(append([]byte{0x00, 0x04}, make([]byte, 32)...), pubGood, priv),
		"well-formed, wrong attrs": encodeTPMBlob(testSRKName, pubLoose, priv),
	}
	for name, b := range cases {
		if _, err := p.Unwrap(b); !errors.Is(err, ErrTPMBlobFormat) {
			t.Errorf("%s: %v, want ErrTPMBlobFormat", name, err)
		}
	}
	if opened {
		t.Error("the TPM was opened for a malformed blob")
	}
	// The good layout passes the format checks (and then needs a TPM).
	if _, _, _, err := decodeTPMBlob(good); err != nil {
		t.Errorf("good blob: %v", err)
	}
}

// fakeTPM answers every command with an error; createSRKFn is replaced
// in these tests, so only FlushContext reaches it.
type fakeTPM struct{}

func (fakeTPM) Send([]byte) ([]byte, error) { return nil, errors.New("fake TPM") }
func (fakeTPM) Close() error                { return nil }

// chooseEnv sets up device paths and injected TPM answers for one test.
// srkErrs are returned by successive storage-key creations (nil means
// success); openErr is returned by opening the device.
func chooseEnv(t *testing.T, rm, raw bool, openErr error, srkErrs ...error) *int {
	t.Helper()
	dir := t.TempDir()
	oRM, oRaw, oSys, oOpen, oSRK, oDelay := tpmRMDevice, tpmRawDevice, tpmSysGlob, openTPMDevice, createSRKFn, tpmRetryDelay
	t.Cleanup(func() {
		tpmRMDevice, tpmRawDevice, tpmSysGlob, openTPMDevice, createSRKFn, tpmRetryDelay = oRM, oRaw, oSys, oOpen, oSRK, oDelay
	})
	tpmRMDevice, tpmRawDevice = filepath.Join(dir, "tpmrm0"), filepath.Join(dir, "tpm0")
	tpmSysGlob = filepath.Join(dir, "sys", "tpm*")
	if rm {
		os.WriteFile(tpmRMDevice, nil, 0o600)
	}
	if raw {
		os.WriteFile(tpmRawDevice, nil, 0o600)
	}
	tpmRetryDelay = time.Millisecond
	openTPMDevice = func(string) (transport.TPMCloser, error) {
		if openErr != nil {
			return nil, openErr
		}
		return fakeTPM{}, nil
	}
	calls := new(int)
	createSRKFn = func(transport.TPM) (*srk, error) {
		i := *calls
		*calls++
		if i < len(srkErrs) && srkErrs[i] != nil {
			return nil, srkErrs[i]
		}
		return &srk{handle: 0x80000000}, nil
	}
	return calls
}

func TestChooseNoTPM(t *testing.T) {
	chooseEnv(t, false, false, nil)
	c, err := ChooseProtector(ChooseOptions{})
	if err != nil || c.Protector != PassphraseName || c.MachineBound || !strings.Contains(c.Reason, "no TPM found") {
		t.Fatalf("choice %+v, %v", c, err)
	}
	if c.Notice() != NotMachineBound {
		t.Errorf("notice %q", c.Notice())
	}
}

// The kernel lists a TPM but the device nodes are missing: an error,
// not a silent fallback.
func TestChooseSysfsOnly(t *testing.T) {
	chooseEnv(t, false, false, nil)
	sysDir := filepath.Dir(tpmSysGlob)
	if err := os.MkdirAll(filepath.Join(sysDir, "tpm0"), 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := ChooseProtector(ChooseOptions{})
	if err == nil || !strings.Contains(err.Error(), "the kernel lists a TPM") {
		t.Fatalf("choice %+v, %v", c, err)
	}
	c, err = ChooseProtector(ChooseOptions{AllowPassphraseFallback: true})
	if err != nil || c.Protector != PassphraseName || !strings.Contains(c.Reason, "the kernel lists a TPM") {
		t.Fatalf("with fallback allowed: %+v, %v", c, err)
	}
}

func TestChooseWorkingTPM(t *testing.T) {
	calls := chooseEnv(t, true, true, nil, tpm2.TPMRCRetry, tpm2.TPMRCTesting, nil)
	c, err := ChooseProtector(ChooseOptions{})
	if err != nil || c.Protector != TPMName || !c.MachineBound || c.Notice() != "" {
		t.Fatalf("choice %+v, %v", c, err)
	}
	if *calls != 3 {
		t.Errorf("%d attempts, want 3 (two transient answers retried)", *calls)
	}
}

// A TPM that is present but does not work is an error naming the cause
// and the fix, unless the operator allows the passphrase.
func TestChoosePresentButFailing(t *testing.T) {
	busy := []error{tpm2.TPMRCYielded, tpm2.TPMRCYielded, tpm2.TPMRCYielded, tpm2.TPMRCYielded, tpm2.TPMRCYielded}
	cases := []struct {
		name    string
		rm, raw bool
		openErr error
		srkErrs []error
		want    string
		is      error
	}{
		{"no resource manager", false, true, nil, nil, "resource manager", nil},
		{"permission denied", true, true, os.ErrPermission, nil, "tss group", nil},
		{"owner password", true, false, nil, []error{tpm2.TPMRCBadAuth}, "owner (storage) hierarchy has a password", nil},
		{"failure mode", true, false, nil, []error{tpm2.TPMRCFailure}, "failure mode", nil},
		{"storage key fails", true, false, nil, []error{tpm2.TPMRCHierarchy}, "did not create its storage key", nil},
		{"busy after retries", true, false, nil, busy, "busy", ErrTPMBusy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := chooseEnv(t, c.rm, c.raw, c.openErr, c.srkErrs...)
			ch, err := ChooseProtector(ChooseOptions{})
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "passphrase instead") {
				t.Fatalf("choice %+v, err %v; want an error mentioning %q", ch, err, c.want)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Errorf("error %v is not %v", err, c.is)
			}
			if c.is == ErrTPMBusy && *calls != tpmAttempts {
				t.Errorf("%d attempts, want %d", *calls, tpmAttempts)
			}
			chooseEnv(t, c.rm, c.raw, c.openErr, c.srkErrs...)
			ch, err = ChooseProtector(ChooseOptions{AllowPassphraseFallback: true})
			if err != nil || ch.Protector != PassphraseName || !strings.Contains(ch.Reason, c.want) {
				t.Fatalf("with fallback allowed: %+v, %v", ch, err)
			}
		})
	}
}

// Transient and definite load failures are told apart.
func TestClassifyLoad(t *testing.T) {
	if err := classifyLoad("x", tpm2.TPMRCRetry); !errors.Is(err, tpm2.TPMRCRetry) || errors.Is(err, ErrTPMUnseal) {
		t.Errorf("transient: %v", err)
	}
	for _, rc := range []tpm2.TPMRC{tpm2.TPMRCIntegrity, tpm2.TPMRCBinding} {
		if err := classifyLoad("x", rc); !errors.Is(err, ErrTPMUnseal) {
			t.Errorf("%v: %v", rc, err)
		}
	}
	if err := classifyLoad("x", tpm2.TPMRCFailure); errors.Is(err, ErrTPMUnseal) || errors.Is(err, ErrTPMMismatch) {
		t.Errorf("failure mode reported as definite: %v", err)
	}
	err := withRetry(func() error { return tpm2.TPMRCRetry })
	if !errors.Is(err, ErrTPMBusy) || strings.Contains(err.Error(), "another computer") {
		t.Errorf("busy: %v", err)
	}
}

// This computer's TPM, only when asked for.
func TestRealTPM(t *testing.T) {
	if os.Getenv(realTPMEnv) != "1" {
		t.Skipf("set %s=1 to use this computer's TPM", realTPMEnv)
	}
	c, err := ChooseProtector(ChooseOptions{})
	if err != nil || c.Protector != TPMName {
		t.Skipf("no usable TPM: %v %s", err, c.Reason)
	}
	p := NewTPM(DefaultTPMDevice)
	blob, err := p.Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unwrap(blob)
	if err != nil || !bytes.Equal(got, dataKey()) {
		t.Fatalf("Unwrap: %v", err)
	}
}
