//go:build linux && cgo

package protect

// Tests against the Microsoft TPM 2.0 reference simulator (go-tpm-tools,
// built with cgo), on the Linux CI job. The simulator is one global
// instance; each test opens and closes it in turn. A fixed seed stands
// for one TPM; another seed for another computer's TPM.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
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
	_, err = simProtector(2).Unwrap(blob)
	if !errors.Is(err, ErrTPMMismatch) || !strings.Contains(err.Error(), "cleared or replaced") {
		t.Fatalf("Unwrap on another TPM = %v, want ErrTPMMismatch", err)
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
	nameLen := int(blob[1])<<8 | int(blob[2])
	pubAt := 1 + 2 + nameLen
	pubLen := int(blob[pubAt])<<8 | int(blob[pubAt+1])
	privStart := pubAt + 2 + pubLen + 2
	// A changed SRK Name: refused as a mismatch before any load.
	b := append([]byte{}, blob...)
	b[1+2+nameLen-1] ^= 0x01
	if _, err := p.Unwrap(b); !errors.Is(err, ErrTPMMismatch) {
		t.Errorf("SRK Name changed: %v, want ErrTPMMismatch", err)
	}
	cases := map[string]int{
		"public, last byte":  pubAt + 2 + pubLen - 1,
		"private, first":     privStart + 2,
		"private, middle":    privStart + (len(blob)-privStart)/2,
		"private, last byte": len(blob) - 1,
	}
	for name, i := range cases {
		b := append([]byte{}, blob...)
		b[i] ^= 0x01
		_, err := p.Unwrap(b)
		if !errors.Is(err, ErrTPMUnseal) && !errors.Is(err, ErrTPMBlobFormat) && !errors.Is(err, ErrTPMMismatch) {
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
	dir := t.TempDir()
	oRM, oRaw, oOpen := tpmRMDevice, tpmRawDevice, openTPMDevice
	defer func() { tpmRMDevice, tpmRawDevice, openTPMDevice = oRM, oRaw, oOpen }()
	tpmRMDevice, tpmRawDevice = filepath.Join(dir, "tpmrm0"), filepath.Join(dir, "tpm0")
	if err := os.WriteFile(tpmRMDevice, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	open := simProtector(1).open
	openTPMDevice = func(string) (transport.TPMCloser, error) { return open() }
	c, err := ChooseProtector(ChooseOptions{})
	if err != nil || c.Protector != TPMName || !c.MachineBound {
		t.Fatalf("choice %+v, %v", c, err)
	}
}

// recordingTPM keeps every command and response.
type recordingTPM struct {
	inner transport.TPMCloser
	log   *[][]byte
}

func (r recordingTPM) Send(cmd []byte) ([]byte, error) {
	*r.log = append(*r.log, append([]byte{}, cmd...))
	rsp, err := r.inner.Send(cmd)
	*r.log = append(*r.log, append([]byte{}, rsp...))
	return rsp, err
}
func (r recordingTPM) Close() error { return r.inner.Close() }

// The data key never crosses the wire in the clear: no command or
// response of Wrap or Unwrap contains it.
func TestTPMWireNeverCarriesKey(t *testing.T) {
	var log [][]byte
	sim := simProtector(1)
	p := &TPM{device: "simulator", open: func() (transport.TPMCloser, error) {
		inner, err := sim.open()
		if err != nil {
			return nil, err
		}
		return recordingTPM{inner: inner, log: &log}, nil
	}}
	key := make([]byte, state.DataKeyLen)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	blob, err := p.Wrap(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unwrap(blob)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("Unwrap: %v", err)
	}
	if len(log) < 8 {
		t.Fatalf("only %d messages recorded", len(log))
	}
	for i, m := range log {
		for _, frag := range [][]byte{key, key[:16], key[16:]} {
			if bytes.Contains(m, frag) {
				t.Fatalf("message %d carries the data key (or half of it) in the clear", i)
			}
		}
	}
}

// A transient answer during Unwrap is retried.
func TestTPMUnwrapRetriesTransient(t *testing.T) {
	p := simProtector(1)
	blob, err := p.Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	oSRK, oDelay := createSRKFn, tpmRetryDelay
	defer func() { createSRKFn, tpmRetryDelay = oSRK, oDelay }()
	tpmRetryDelay = time.Millisecond
	n := 0
	createSRKFn = func(tpm transport.TPM) (*srk, error) {
		n++
		if n == 1 {
			return nil, tpm2.TPMRCRetry
		}
		return oSRK(tpm)
	}
	if got, err := p.Unwrap(blob); err != nil || !bytes.Equal(got, dataKey()) {
		t.Fatalf("Unwrap: %v", err)
	}
	if n != 2 {
		t.Errorf("%d attempts, want 2", n)
	}
}

// swapSRKPublic changes the last byte of the public area in every
// CreatePrimary response (the ECC point's y), leaving the Name as the
// TPM sent it.
type swapSRKPublic struct{ inner transport.TPMCloser }

func (s swapSRKPublic) Send(cmd []byte) ([]byte, error) {
	rsp, err := s.inner.Send(cmd)
	if err != nil || len(cmd) < 10 || binary.BigEndian.Uint32(cmd[6:10]) != uint32(tpm2.TPMCCCreatePrimary) {
		return rsp, err
	}
	// header (10) || object handle (4) || parameter size (4) || TPM2B_PUBLIC
	if len(rsp) < 20 || binary.BigEndian.Uint32(rsp[6:10]) != 0 {
		return rsp, err
	}
	n := int(binary.BigEndian.Uint16(rsp[18:20]))
	out := append([]byte{}, rsp...)
	out[20+n-1] ^= 0x01
	return out, nil
}
func (s swapSRKPublic) Close() error { return s.inner.Close() }

// A CreatePrimary answer whose public key does not match its Name is
// refused before any session is salted to it.
func TestTPMRefusesInconsistentSRK(t *testing.T) {
	sim := simProtector(1)
	p := &TPM{device: "simulator", open: func() (transport.TPMCloser, error) {
		inner, err := sim.open()
		if err != nil {
			return nil, err
		}
		return swapSRKPublic{inner}, nil
	}}
	if _, err := p.Wrap(dataKey()); !errors.Is(err, ErrTPMInconsistent) {
		t.Fatalf("Wrap with a swapped SRK public key = %v, want ErrTPMInconsistent", err)
	}
	blob, err := sim.Wrap(dataKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unwrap(blob); !errors.Is(err, ErrTPMInconsistent) {
		t.Fatalf("Unwrap with a swapped SRK public key = %v, want ErrTPMInconsistent", err)
	}
}
