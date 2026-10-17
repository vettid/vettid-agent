//go:build linux && cgo

package protect

// Tests against the Microsoft TPM 2.0 reference simulator (go-tpm-tools,
// built with cgo), on the Linux CI job. The simulator is one global
// instance; each test opens and closes it in turn. A fixed seed stands
// for one TPM; another seed for another computer's TPM.

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	"github.com/vettid/vettid-agent/internal/state"
)

type simTPM struct{ s *simulator.Simulator }

func (t simTPM) Send(cmd []byte) ([]byte, error) { return tpmutil.RunCommandRaw(t.s, cmd) }
func (t simTPM) Close() error                    { return t.s.Close() }

// simProtector is a TPM protector whose every operation opens the
// simulator with the given seed (one seed, one TPM).
func simProtector(seed int64) *TPM {
	return &TPM{device: "simulator", open: func() (transport.TPMCloser, error) {
		s, err := simulator.GetWithFixedSeedInsecure(seed)
		if err != nil {
			return nil, err
		}
		return simTPM{s}, nil
	}}
}

func TestTPMRoundTrip(t *testing.T) {
	p := simProtector(1)
	blob, err := p.Wrap(dataKey())
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if blob[0] != tpmBlobVersion {
		t.Errorf("version %d", blob[0])
	}
	got, err := p.Unwrap(blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, dataKey()) {
		t.Fatal("unsealed key differs")
	}
	// Each seal is a new object.
	blob2, err := p.Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(blob, blob2) {
		t.Error("two seals gave the same blob")
	}
}

// A blob sealed by one TPM does not unseal on another.
func TestTPMOtherTPMRefused(t *testing.T) {
	blob, err := simProtector(1).Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := simProtector(2).Unwrap(blob); !errors.Is(err, ErrTPMUnseal) {
		t.Fatalf("Unwrap on another TPM = %v, want ErrTPMUnseal", err)
	}
	if _, err := simProtector(1).Unwrap(blob); err != nil {
		t.Fatalf("Unwrap on the same TPM after the other: %v", err)
	}
}

// A tampered blob is refused: by the format checks, or by the TPM's
// integrity check of the private part and its binding to the public.
func TestTPMTamperedRefused(t *testing.T) {
	p := simProtector(1)
	blob, err := p.Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	pubLen := int(blob[1])<<8 | int(blob[2])
	privStart := 1 + 2 + pubLen + 2
	cases := map[string]int{
		"public, last byte":  1 + 2 + pubLen - 1,
		"private, first":     privStart + 2,
		"private, middle":    privStart + (len(blob)-privStart)/2,
		"private, last byte": len(blob) - 1,
	}
	for name, i := range cases {
		b := append([]byte{}, blob...)
		b[i] ^= 0x01
		_, err := p.Unwrap(b)
		if !errors.Is(err, ErrTPMUnseal) && !errors.Is(err, ErrTPMBlobFormat) {
			t.Errorf("%s: Unwrap = %v, want a refusal", name, err)
		}
		if err == nil {
			t.Errorf("%s: a tampered blob unsealed", name)
		}
	}
}

// A state file created with the TPM protector opens again, and not on
// another TPM.
func TestTPMStateFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Create(simProtector(1), []byte("device state")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	resolve := func(p *TPM) state.Resolver {
		return func(name string) state.Protector {
			if name == TPMName {
				return p
			}
			return nil
		}
	}
	if _, err := s.Load(resolve(simProtector(2))); !errors.Is(err, state.ErrUnwrap) {
		t.Fatalf("Load on another TPM = %v, want ErrUnwrap", err)
	}
	got, err := s.Load(resolve(simProtector(1)))
	if err != nil || string(got) != "device state" {
		t.Fatalf("Load = %q, %v", got, err)
	}
	if err := s.Wipe(nil); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
}

// With a working TPM, the TPM protector is chosen.
func TestChooseTPMWithSimulator(t *testing.T) {
	c := chooseTPM("simulator", simProtector(1).open)
	if c.Protector != TPMName || !c.MachineBound || c.Notice() != "" {
		t.Fatalf("choice %+v", c)
	}
}
