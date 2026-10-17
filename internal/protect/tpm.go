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
//	blob = version (1 byte, 0x02) || len(srk) (2, big-endian) || srk
//	       || len(pub) (2, big-endian) || pub || len(priv) (2, big-endian) || priv
//	srk  = the Name of the storage root key the object was sealed under
//	pub  = the sealed object's TPM2B_PUBLIC, priv its TPM2B_PRIVATE,
//	       as the TPM returned them (tpm2.Marshal)
//
// with nothing after; any other version is refused (0x01, which had no
// SRK Name, was never released). Before loading, the recreated SRK's
// Name is compared with the pinned one: a different Name means a
// different storage seed (the TPM was cleared or replaced, or the file
// is from another computer), reported as ErrTPMMismatch without asking
// the TPM to load anything.
//
// Errors are of three kinds. Definite: ErrTPMMismatch (SRK Name) and
// ErrTPMUnseal (the TPM refused the object's integrity or binding);
// only these say "another computer, cleared TPM or altered file".
// Transient: ErrTPMBusy, after retrying TPM_RC_RETRY, TPM_RC_YIELDED,
// TPM_RC_TESTING and the other warning codes a few times. Anything else
// (the device cannot be opened, the owner hierarchy has a password, the
// TPM is in failure mode) is returned with its cause.
//
// Wipe deletes nothing: the sealed object lives only
// in the blob inside the state file (no persistent handle, no NV index),
// so `forget` destroys it by overwriting and deleting the file. An old
// copy of the state file recovered from the disk afterwards (a backup, a
// file system snapshot, a block an SSD remapped) can still be opened on
// this computer until its TPM is cleared. Opening such a copy needs the
// copy (from a backup, a snapshot or the raw disk) and access to this
// computer's TPM.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"time"

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

	tpmBlobVersion = 2
	maxTPMPart     = 2048
)

// Retry policy for transient TPM answers; tests shorten the delay.
var (
	tpmAttempts   = 5
	tpmRetryDelay = 50 * time.Millisecond
)

var (
	// ErrTPMBlobFormat: the wrapped key is not a TPM protector blob.
	ErrTPMBlobFormat = errors.New("the wrapped key is not in the TPM protector's format")
	// ErrTPMUnseal: the TPM refused the sealed object (integrity or
	// binding): an altered file, or one sealed by another TPM.
	ErrTPMUnseal = errors.New("this TPM refuses the state file's key: the file was altered, or it is from another computer or a cleared TPM")
	// ErrTPMMismatch: the storage root key differs from the one the key
	// was sealed under.
	ErrTPMMismatch = errors.New("the TPM was cleared or replaced, or this file is from another computer")
	// ErrTPMInconsistent: the TPM's answer to creating the storage root
	// key does not hold together (its public area does not match its
	// Name, or is not the template's kind of key).
	ErrTPMInconsistent = errors.New("the TPM's storage root key answer is inconsistent (its public key does not match its Name); the TPM or the path to it may be faulty or tampered with")
	// ErrTPMBusy: the TPM kept answering with a transient code (busy,
	// self-testing, out of memory for objects or sessions).
	ErrTPMBusy = errors.New("the TPM is busy or still starting; try again")
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

// Wipe does nothing: the sealed key exists only in the state file, and
// an old copy of that file recovered from the disk still opens on this
// computer until its TPM is cleared (see the comment at the top of this
// file).
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

// isTransient reports a TPM warning code worth retrying.
func isTransient(err error) bool {
	for _, rc := range []tpm2.TPMRC{tpm2.TPMRCRetry, tpm2.TPMRCYielded, tpm2.TPMRCTesting, tpm2.TPMRCCanceled,
		tpm2.TPMRCContextGap, tpm2.TPMRCObjectMemory, tpm2.TPMRCSessionMemory, tpm2.TPMRCMemory,
		tpm2.TPMRCObjectHandles, tpm2.TPMRCReferenceH0, tpm2.TPMRCNVRate} {
		if errors.Is(err, rc) {
			return true
		}
	}
	return false
}

// withRetry runs op, retrying transient TPM answers; after the last
// attempt a transient answer becomes ErrTPMBusy.
func withRetry(op func() error) error {
	var err error
	for i := 0; i < tpmAttempts; i++ {
		if i > 0 {
			time.Sleep(tpmRetryDelay << (i - 1))
		}
		if err = op(); err == nil || !isTransient(err) {
			return err
		}
	}
	return fmt.Errorf("%w (%v)", ErrTPMBusy, err)
}

// createSRKFn creates the storage root key; tests replace it to inject
// TPM answers.
var createSRKFn = createSRK

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
	// The returned public area must be the template's kind of key, and
	// its Name (computed here) must equal the Name the TPM returned,
	// before any session is salted to that key or its Name is pinned.
	name, err := tpm2.ObjectName(pub)
	if err != nil || !bytes.Equal(name.Buffer, rsp.Name.Buffer) ||
		pub.Type != tpm2.ECCSRKTemplate.Type || pub.NameAlg != tpm2.ECCSRKTemplate.NameAlg ||
		pub.ObjectAttributes != tpm2.ECCSRKTemplate.ObjectAttributes {
		flush(tpm, rsp.ObjectHandle)
		return nil, ErrTPMInconsistent
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
	var blob []byte
	err := withRetry(func() error {
		var err error
		blob, err = t.wrapOnce(dataKey)
		return err
	})
	return blob, err
}

func (t *TPM) wrapOnce(dataKey []byte) ([]byte, error) {
	tpm, err := t.open()
	if err != nil {
		return nil, openError(t.device, err)
	}
	defer tpm.Close()
	k, err := createSRKFn(tpm)
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
	return encodeTPMBlob(k.name.Buffer, tpm2.Marshal(rsp.OutPublic), tpm2.Marshal(rsp.OutPrivate)), nil
}

// Unwrap recreates the storage root key, checks its Name against the
// pinned one, loads the sealed object and unseals the data key.
func (t *TPM) Unwrap(blob []byte) ([]byte, error) {
	srkName, pub, priv, err := decodeTPMBlob(blob)
	if err != nil {
		return nil, err
	}
	var key []byte
	err = withRetry(func() error {
		var err error
		key, err = t.unwrapOnce(srkName, pub, priv)
		return err
	})
	return key, err
}

func (t *TPM) unwrapOnce(srkName []byte, pub *tpm2.TPM2BPublic, priv *tpm2.TPM2BPrivate) ([]byte, error) {
	tpm, err := t.open()
	if err != nil {
		return nil, openError(t.device, err)
	}
	defer tpm.Close()
	k, err := createSRKFn(tpm)
	if err != nil {
		return nil, err
	}
	defer flush(tpm, k.handle)
	if !bytes.Equal(k.name.Buffer, srkName) {
		return nil, ErrTPMMismatch
	}
	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: k.handle, Name: k.name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     *pub,
		InPrivate:    *priv,
	}.Execute(tpm)
	if err != nil {
		return nil, classifyLoad("load the sealed key", err)
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
		return nil, classifyLoad("unseal the key", err)
	}
	key := append([]byte(nil), rsp.OutData.Buffer...)
	clear(rsp.OutData.Buffer)
	if len(key) != state.DataKeyLen {
		clear(key)
		return nil, ErrTPMUnseal
	}
	return key, nil
}

// classifyLoad maps a Load or Unseal failure: transient codes pass
// through for withRetry; integrity, binding, size and value refusals are
// definite (ErrTPMUnseal); anything else keeps its cause.
func classifyLoad(step string, err error) error {
	if isTransient(err) {
		return err
	}
	for _, rc := range []tpm2.TPMRC{tpm2.TPMRCIntegrity, tpm2.TPMRCBinding, tpm2.TPMRCSize, tpm2.TPMRCValue} {
		if errors.Is(err, rc) {
			return ErrTPMUnseal
		}
	}
	return fmt.Errorf("TPM: %s: %w", step, err)
}

// openError names the cause of a failure to open the TPM device.
func openError(device string, err error) error {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("TPM: %s cannot be opened by this user (permission denied): add your user to the tss group (for example `sudo usermod -aG tss $USER`, then log in again)", device)
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("TPM: %s does not exist", device)
	default:
		return fmt.Errorf("TPM: open %s: %w", device, err)
	}
}

func encodeTPMBlob(srkName, pub, priv []byte) []byte {
	out := []byte{tpmBlobVersion}
	for _, part := range [][]byte{srkName, pub, priv} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(part)))
		out = append(out, part...)
	}
	return out
}

// decodeTPMBlob checks the framing and the sealed object's public part
// (a keyed-hash object with this protector's attributes) and returns
// the pinned SRK Name and both parts. Each part must re-marshal to
// exactly its bytes.
func decodeTPMBlob(blob []byte) ([]byte, *tpm2.TPM2BPublic, *tpm2.TPM2BPrivate, error) {
	if len(blob) < 1 || blob[0] != tpmBlobVersion {
		return nil, nil, nil, ErrTPMBlobFormat
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
	srkName, ok0 := part()
	pubB, ok1 := part()
	privB, ok2 := part()
	if !ok0 || !ok1 || !ok2 || len(rest) != 0 {
		return nil, nil, nil, ErrTPMBlobFormat
	}
	// A Name is a 2-byte hash algorithm id and its digest; the SRK's
	// name algorithm is SHA-256.
	if len(srkName) != 2+32 || binary.BigEndian.Uint16(srkName) != uint16(tpm2.TPMAlgSHA256) {
		return nil, nil, nil, ErrTPMBlobFormat
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubB)
	if err != nil || !bytes.Equal(tpm2.Marshal(pub), pubB) {
		return nil, nil, nil, ErrTPMBlobFormat
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privB)
	if err != nil || !bytes.Equal(tpm2.Marshal(priv), privB) {
		return nil, nil, nil, ErrTPMBlobFormat
	}
	contents, err := pub.Contents()
	if err != nil || contents.Type != tpm2.TPMAlgKeyedHash || contents.NameAlg != tpm2.TPMAlgSHA256 ||
		contents.ObjectAttributes != sealTemplate.ObjectAttributes {
		return nil, nil, nil, ErrTPMBlobFormat
	}
	return srkName, pub, priv, nil
}
