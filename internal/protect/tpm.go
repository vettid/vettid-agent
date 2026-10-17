//go:build linux

package protect

// The Linux TPM 2.0 protector (AGENT-PLAN §2 AG3, §4.2, §6 A1.3). The
// data key is sealed to the computer's TPM, so a copy of the state file
// does not open on another computer (LEASH §3.4).
//
// Construction:
//
//   - The parent is the storage root key (SRK) created under the owner
//     (storage) hierarchy from the TCG reference ECC P-256 SRK template
//     (tpm2.ECCSRKTemplate). The TPM derives it from its storage primary
//     seed, so the same template gives the same key on every run; it is
//     created when needed and flushed after, never made persistent.
//   - The data key is sealed in a keyed-hash data object under the SRK
//     with FixedTPM and FixedParent (it cannot be duplicated to another
//     TPM or re-parented), UserWithAuth with an empty auth value, and
//     NoDA. The TPM returns it as a public and an encrypted private part
//     that only this TPM can load.
//   - No PCR policy in v1 (chosen; not in the spec): PCR-bound objects
//     stop unsealing after firmware, bootloader or kernel updates, which
//     would strand a working pairing; the goal here is machine binding,
//     which FixedTPM under this TPM's storage seed gives. Anyone who can
//     use this TPM and read the state file can unseal it; the state file
//     is owner-only (internal/state) and /dev/tpmrm0 is usually limited
//     to root and the tss group.
//   - Commands that carry the data key use a salted HMAC session (salted
//     to the SRK) with AES-128 parameter encryption: Create's sensitive
//     input and Unseal's output do not cross the bus in the clear.
//
// The wrapped blob:
//
//	blob = version (1 byte, 0x01) || len(pub) (2, big-endian) || pub
//	       || len(priv) (2, big-endian) || priv
//	pub  = the sealed object's TPM2B_PUBLIC, priv its TPM2B_PRIVATE,
//	       as the TPM returned them (tpm2.Marshal)
//
// with nothing after; an unknown version is refused.
//
// Wipe deletes nothing: the sealed object lives only in the blob inside
// the state file (no persistent handle, no NV index), so overwriting and
// deleting the state file destroys it. A future version that keeps a
// key in the TPM would delete it in Wipe.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/vettid/vettid-agent/internal/state"
)

const (
	// TPMName is the TPM protector's name in the state file header.
	TPMName = "tpm"
	// DefaultTPMDevice is the kernel's TPM resource manager.
	DefaultTPMDevice = "/dev/tpmrm0"

	tpmBlobVersion = 1
	maxTPMPart     = 2048
)

var (
	// ErrTPMBlobFormat: the wrapped key is not a TPM protector blob.
	ErrTPMBlobFormat = errors.New("the wrapped key is not in the TPM protector's format")
	// ErrTPMUnseal: this TPM could not load or unseal the blob (another
	// computer's TPM, a cleared TPM, or an altered blob).
	ErrTPMUnseal = errors.New("this computer's TPM cannot open the state file's key (another computer, a cleared TPM, or an altered file)")
)

// TPM is the TPM protector. It opens the TPM for each operation and
// closes it after.
type TPM struct {
	device string
	open   func() (transport.TPMCloser, error)
}

var _ state.Protector = (*TPM)(nil)

// NewTPM returns a TPM protector using the TPM resource manager at
// device (DefaultTPMDevice).
func NewTPM(device string) *TPM {
	return &TPM{device: device, open: func() (transport.TPMCloser, error) { return linuxtpm.Open(device) }}
}

// Name returns "tpm".
func (t *TPM) Name() string { return TPMName }

// Wipe does nothing: the sealed key exists only in the state file (see
// the package comment above).
func (t *TPM) Wipe() error { return nil }

// sealTemplate is the sealed data object's public template.
var sealTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgKeyedHash,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:     true,
		FixedParent:  true,
		UserWithAuth: true,
		NoDA:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
		Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
	}),
}

type srk struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    tpm2.TPMTPublic
}

// createSRK creates the storage root key from the fixed template.
func createSRK(tpm transport.TPM) (*srk, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM: create the storage root key: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		flush(tpm, rsp.ObjectHandle)
		return nil, fmt.Errorf("TPM: storage root key: %w", err)
	}
	return &srk{handle: rsp.ObjectHandle, name: rsp.Name, pub: *pub}, nil
}

func flush(tpm transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(tpm)
}

// session is a salted HMAC session with parameter encryption in dir.
func (k *srk) session(dir tpm2.AuthOption) tpm2.Session {
	return tpm2.HMAC(tpm2.TPMAlgSHA256, 16, dir, tpm2.Salted(k.handle, k.pub))
}

// Wrap seals dataKey to this TPM.
func (t *TPM) Wrap(dataKey []byte) ([]byte, error) {
	if len(dataKey) != state.DataKeyLen {
		return nil, errors.New("TPM protector: data key length")
	}
	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("TPM: open %s: %w", t.device, err)
	}
	defer tpm.Close()
	k, err := createSRK(tpm)
	if err != nil {
		return nil, err
	}
	defer flush(tpm, k.handle)
	rsp, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: k.handle,
			Name:   k.name,
			Auth:   k.session(tpm2.AESEncryption(128, tpm2.EncryptIn)),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: dataKey}),
			},
		},
		InPublic: tpm2.New2B(sealTemplate),
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("TPM: seal the key: %w", err)
	}
	return encodeTPMBlob(tpm2.Marshal(rsp.OutPublic), tpm2.Marshal(rsp.OutPrivate)), nil
}

// Unwrap loads the sealed object under this TPM's storage root key and
// unseals the data key.
func (t *TPM) Unwrap(blob []byte) ([]byte, error) {
	pub, priv, err := decodeTPMBlob(blob)
	if err != nil {
		return nil, err
	}
	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("TPM: open %s: %w", t.device, err)
	}
	defer tpm.Close()
	k, err := createSRK(tpm)
	if err != nil {
		return nil, err
	}
	defer flush(tpm, k.handle)
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: k.handle, Name: k.name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     *pub,
		InPrivate:    *priv,
	}.Execute(tpm)
	if err != nil {
		return nil, ErrTPMUnseal
	}
	defer flush(tpm, loaded.ObjectHandle)
	rsp, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   k.session(tpm2.AESEncryption(128, tpm2.EncryptOut)),
		},
	}.Execute(tpm)
	if err != nil {
		return nil, ErrTPMUnseal
	}
	key := append([]byte(nil), rsp.OutData.Buffer...)
	clear(rsp.OutData.Buffer)
	if len(key) != state.DataKeyLen {
		clear(key)
		return nil, ErrTPMUnseal
	}
	return key, nil
}

func encodeTPMBlob(pub, priv []byte) []byte {
	out := []byte{tpmBlobVersion}
	out = binary.BigEndian.AppendUint16(out, uint16(len(pub)))
	out = append(out, pub...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(priv)))
	return append(out, priv...)
}

// decodeTPMBlob checks the framing and the sealed object's public part
// (a keyed-hash object with this protector's attributes) and returns
// both parts. Each part must re-marshal to exactly its bytes.
func decodeTPMBlob(blob []byte) (*tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, error) {
	if len(blob) < 1 || blob[0] != tpmBlobVersion {
		return nil, nil, ErrTPMBlobFormat
	}
	rest := blob[1:]
	part := func() ([]byte, bool) {
		if len(rest) < 2 {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(rest))
		if n == 0 || n > maxTPMPart || len(rest) < 2+n {
			return nil, false
		}
		p := rest[2 : 2+n]
		rest = rest[2+n:]
		return p, true
	}
	pubB, ok1 := part()
	privB, ok2 := part()
	if !ok1 || !ok2 || len(rest) != 0 {
		return nil, nil, ErrTPMBlobFormat
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubB)
	if err != nil || !bytes.Equal(tpm2.Marshal(pub), pubB) {
		return nil, nil, ErrTPMBlobFormat
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privB)
	if err != nil || !bytes.Equal(tpm2.Marshal(priv), privB) {
		return nil, nil, ErrTPMBlobFormat
	}
	contents, err := pub.Contents()
	if err != nil || contents.Type != tpm2.TPMAlgKeyedHash || contents.NameAlg != tpm2.TPMAlgSHA256 ||
		contents.ObjectAttributes != sealTemplate.ObjectAttributes {
		return nil, nil, ErrTPMBlobFormat
	}
	return pub, priv, nil
}
