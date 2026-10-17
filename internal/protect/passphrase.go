// Package protect holds the protectors that wrap the state file's data
// key (AGENT-PLAN §2 AG3, §3.1, §4.2). Each implements state.Protector.
//
// This file is the passphrase protector, for computers without a
// platform protector (headless servers, containers). It is portable by
// nature: the state file and the passphrase open it anywhere, so it is
// not bound to the computer (AGENT-PLAN §4.2 "Headless"; §10 risk 3).
//
// Neither the passphrase nor any key derived from it is logged or put in
// an error. In-memory copies are cleared when no longer needed, as far
// as Go allows: copies the runtime made (garbage collection, stack
// growth, string conversions in libraries) cannot be reached. This is
// best effort, not a guarantee.
package protect

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"

	"github.com/vettid/vettid-agent/internal/state"
)

// PassphraseName is the passphrase protector's name in the state file
// header.
const PassphraseName = "passphrase"

// NotMachineBound is the plain notice for the operator (AGENT-PLAN §11
// "Not machine-bound"), shown by `status` for this protector.
const NotMachineBound = "Keys are protected by your passphrase only, not bound to this computer."

// Params are Argon2id parameters.
type Params struct {
	Time      uint32 // iterations (t)
	MemoryKiB uint32 // memory in KiB (m)
	Threads   uint8  // parallelism (p)
}

// The production parameters. New wraps use defaultParams; Unwrap refuses
// anything below minParams. Both are the vault's parameters for new
// password seals (VAULT-MESSAGING §3.5.1 "Password key": t = 3,
// m = 64 MiB, p = 1; the vault itself refuses below t = 1, m = 8 MiB):
// this protector does not accept less than what it writes. Tests lower
// them through these variables only, to keep their cost small.
var (
	defaultParams = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 1}
	minParams     = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 1}
)

// maxParams bounds what Unwrap will compute, so that an altered file
// cannot make the process allocate without limit before the
// authentication fails. 1 GiB is the vault's highest Argon2id memory
// (VAULT-MESSAGING §11.14.3, the recovery wrap).
var maxParams = Params{Time: 32, MemoryKiB: 1024 * 1024, Threads: 16}

// DefaultParams returns the parameters new wraps use.
func DefaultParams() Params { return defaultParams }

// MinParams returns the lowest parameters Unwrap accepts.
func MinParams() Params { return minParams }

// The wrapped data key ("blob"):
//
//	blob = version (1 byte, 0x01) || t (4, big-endian) || m (4, big-endian, KiB)
//	       || p (1) || salt (16) || nonce (24) || ct (48)
//	K    = Argon2id(passphrase, salt, t, m, p, 32)
//	ct   = XChaCha20-Poly1305(K, nonce, aad = blobLabel || blob[0:26], data key)
//
// The passphrase is its UTF-8 bytes after normalization to NFC (as the
// vault normalizes passwords, VAULT-MESSAGING §3.5.1). The parameters and
// salt are in the blob, so they can be raised later; they are also
// authenticated, although a changed salt or parameter already yields a
// different K.
const (
	blobVersion = 1
	saltLen     = 16
	blobHdrLen  = 1 + 4 + 4 + 1 + saltLen
	blobLen     = blobHdrLen + chacha20poly1305.NonceSizeX + state.DataKeyLen + chacha20poly1305.Overhead
	blobLabel   = "vettid-agent/protect/passphrase/v1\x00"

	// MinChars and MinClasses are the strength rules (AGENT-PLAN §1).
	MinChars   = 12
	MinClasses = 3
	// MaxBytes is the longest passphrase accepted (the vault's password
	// limit, VAULT-MESSAGING §3.5.1).
	MaxBytes = 1024
)

var (
	// ErrWrongPassphrase: the wrapped key does not open with this
	// passphrase (or it was altered).
	ErrWrongPassphrase = errors.New("wrong passphrase, or the state file was altered")
	// ErrWeakPassphrase: a new passphrase does not meet the strength
	// rules. The error's text says which rule.
	ErrWeakPassphrase = errors.New("passphrase too weak")
	// ErrParamsBelowMinimum: the wrapped key's Argon2id parameters are
	// below the minimum.
	ErrParamsBelowMinimum = errors.New("the passphrase key's Argon2id parameters are below the minimum")
	// ErrParamsAboveMaximum: the parameters exceed what this build will
	// compute.
	ErrParamsAboveMaximum = errors.New("the passphrase key's Argon2id parameters are above the maximum")
	// ErrBlobFormat: the wrapped key is not a passphrase protector blob.
	ErrBlobFormat = errors.New("the wrapped key is not in the passphrase protector's format")
	// ErrWiped: the protector's passphrase was wiped.
	ErrWiped = errors.New("passphrase protector: passphrase was wiped")
)

// Passphrase is the passphrase protector.
type Passphrase struct {
	pass []byte // NFC
}

var _ state.Protector = (*Passphrase)(nil)

// NewPassphrase returns a passphrase protector. It copies pass (the
// caller should clear its own copy). Strength is checked when wrapping
// (a new state file), not when opening one.
func NewPassphrase(pass []byte) (*Passphrase, error) {
	if len(pass) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if len(pass) > MaxBytes {
		return nil, fmt.Errorf("passphrase longer than %d bytes", MaxBytes)
	}
	if !utf8.Valid(pass) {
		return nil, errors.New("passphrase is not valid UTF-8 text")
	}
	return &Passphrase{pass: nfcCopy(pass)}, nil
}

// Name returns "passphrase".
func (p *Passphrase) Name() string { return PassphraseName }

// Wrap derives a key from the passphrase with a fresh salt and wraps
// dataKey under it. It refuses a passphrase that fails CheckStrength.
func (p *Passphrase) Wrap(dataKey []byte) ([]byte, error) {
	if p.pass == nil {
		return nil, ErrWiped
	}
	if len(dataKey) != state.DataKeyLen {
		return nil, errors.New("passphrase protector: data key length")
	}
	if err := CheckStrength(p.pass); err != nil {
		return nil, err
	}
	return p.wrap(dataKey, defaultParams)
}

func (p *Passphrase) wrap(dataKey []byte, params Params) ([]byte, error) {
	blob := make([]byte, blobHdrLen, blobLen)
	blob[0] = blobVersion
	binary.BigEndian.PutUint32(blob[1:], params.Time)
	binary.BigEndian.PutUint32(blob[5:], params.MemoryKiB)
	blob[9] = params.Threads
	if _, err := rand.Read(blob[10:blobHdrLen]); err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	k := argon2.IDKey(p.pass, blob[10:blobHdrLen], params.Time, params.MemoryKiB, params.Threads, chacha20poly1305.KeySize)
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	blob = append(blob, nonce...)
	blob = aead.Seal(blob, nonce, dataKey, aad(blob[:blobHdrLen]))
	slog.Debug("passphrase protector: wrapped data key",
		"t", params.Time, "m_kib", params.MemoryKiB, "p", params.Threads)
	return blob, nil
}

// Unwrap derives the key with the blob's salt and parameters and opens
// the data key. Parameters below MinParams or above the maximum are
// refused before any derivation.
func (p *Passphrase) Unwrap(blob []byte) ([]byte, error) {
	if p.pass == nil {
		return nil, ErrWiped
	}
	if len(blob) != blobLen || blob[0] != blobVersion {
		return nil, ErrBlobFormat
	}
	params := Params{
		Time:      binary.BigEndian.Uint32(blob[1:]),
		MemoryKiB: binary.BigEndian.Uint32(blob[5:]),
		Threads:   blob[9],
	}
	if params.Time < minParams.Time || params.MemoryKiB < minParams.MemoryKiB || params.Threads < minParams.Threads || params.Threads == 0 {
		return nil, ErrParamsBelowMinimum
	}
	if params.Time > maxParams.Time || params.MemoryKiB > maxParams.MemoryKiB || params.Threads > maxParams.Threads {
		return nil, ErrParamsAboveMaximum
	}
	salt := blob[10:blobHdrLen]
	nonce := blob[blobHdrLen : blobHdrLen+chacha20poly1305.NonceSizeX]
	ct := blob[blobHdrLen+chacha20poly1305.NonceSizeX:]
	k := argon2.IDKey(p.pass, salt, params.Time, params.MemoryKiB, params.Threads, chacha20poly1305.KeySize)
	defer clear(k)
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	dataKey, err := aead.Open(nil, nonce, ct, aad(blob[:blobHdrLen]))
	if err != nil {
		slog.Debug("passphrase protector: data key did not open")
		return nil, ErrWrongPassphrase
	}
	slog.Debug("passphrase protector: unwrapped data key",
		"t", params.Time, "m_kib", params.MemoryKiB, "p", params.Threads)
	return dataKey, nil
}

// Wipe clears the passphrase from memory (best effort). The protector
// keeps no key outside the state file, so there is nothing else to
// delete. After Wipe, Wrap and Unwrap fail.
func (p *Passphrase) Wipe() error {
	clear(p.pass)
	p.pass = nil
	return nil
}

// Equal reports, in constant time, whether two passphrases are the same
// after normalization; for a confirmation prompt.
func Equal(a, b []byte) bool {
	na, nb := nfcCopy(a), nfcCopy(b)
	defer clear(na)
	defer clear(nb)
	return subtle.ConstantTimeCompare(na, nb) == 1
}

// nfcCopy returns a new slice holding b normalized to NFC. norm may
// return b itself or a new slice; an intermediate copy is cleared.
func nfcCopy(b []byte) []byte {
	n := norm.NFC.Bytes(b)
	out := append(make([]byte, 0, len(n)), n...)
	if len(n) > 0 && len(b) > 0 && &n[0] != &b[0] {
		clear(n)
	}
	return out
}

func aad(hdr []byte) []byte {
	return append([]byte(blobLabel), hdr...)
}
