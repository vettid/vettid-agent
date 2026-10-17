//go:build linux

package protect

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/vettid/vettid-agent/internal/state"
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

// Blobs that are not this protector's format are refused before the
// TPM is opened.
func TestTPMBlobFormatRefused(t *testing.T) {
	opened := false
	p := &TPM{device: "test", open: func() (transport.TPMCloser, error) {
		opened = true
		return nil, errors.New("must not be opened")
	}}
	good := encodeTPMBlob([]byte{0, 1, 0xaa}, []byte{0, 1, 0xbb})
	cases := map[string][]byte{
		"empty":          nil,
		"version":        append([]byte{2}, good[1:]...),
		"truncated":      good[:len(good)-1],
		"trailing":       append(append([]byte{}, good...), 0),
		"zero length":    {1, 0, 0, 0, 0},
		"public garbage": good,
	}
	for name, b := range cases {
		if _, err := p.Unwrap(b); !errors.Is(err, ErrTPMBlobFormat) {
			t.Errorf("%s: %v, want ErrTPMBlobFormat", name, err)
		}
	}
	if opened {
		t.Error("the TPM was opened for a malformed blob")
	}
}

// No TPM device: the passphrase protector is chosen, with the reason.
func TestChooseFallsBackWithoutTPM(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "tpmrm0")
	c := chooseTPM(dev, func() (transport.TPMCloser, error) { return linuxtpm.Open(dev) })
	if c.Protector != PassphraseName || c.MachineBound || !strings.Contains(c.Reason, "no TPM found") {
		t.Fatalf("choice %+v", c)
	}
	if c.Notice() != NotMachineBound {
		t.Errorf("notice %q", c.Notice())
	}
	// A file that is not a device.
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c = chooseTPM(dev, func() (transport.TPMCloser, error) { return linuxtpm.Open(dev) })
	if c.Protector != PassphraseName || !strings.Contains(c.Reason, "cannot be opened") {
		t.Fatalf("choice %+v", c)
	}
	// Permission denied.
	c = chooseTPM(dev, func() (transport.TPMCloser, error) { return nil, os.ErrPermission })
	if c.Protector != PassphraseName || !strings.Contains(c.Reason, "permission denied") {
		t.Fatalf("choice %+v", c)
	}
}

// This computer's TPM, only when asked for.
func TestRealTPM(t *testing.T) {
	if os.Getenv(realTPMEnv) != "1" {
		t.Skipf("set %s=1 to use this computer's TPM", realTPMEnv)
	}
	c := ChooseProtector()
	if c.Protector != TPMName {
		t.Skipf("no usable TPM: %s", c.Reason)
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
	_ = state.DataKeyLen
}
