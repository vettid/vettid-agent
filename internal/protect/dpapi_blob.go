package protect

// The Windows DPAPI protector's blob format (AGENT-PLAN §6 A1.4). The
// format checks are here, without a build tag, so that they are tested
// on every platform; the DPAPI calls are in dpapi_windows.go.
//
// The wrapped blob:
//
//	blob  = version (1 byte, 0x01) || dpapi
//	dpapi = what CryptProtectData returned, unchanged
//
// with nothing after. The DPAPI part is checked before it is given to
// Windows: its framing (every length field, nothing left over), the
// DPAPI blob version 1 and provider GUID, master key version 1, the
// flags (no CRYPTPROTECT_LOCAL_MACHINE: a machine-scope blob, which any
// user of the computer could open, is refused), this protector's
// description, and the algorithms (AES with SHA-2 only). Microsoft does
// not document this layout; it is the long-known one (as read by
// forensic tools such as dpapick and mimikatz). Wrap checks its own
// output against the same rules, so a Windows release that changed the
// layout would fail at pairing (and the protector would not be chosen),
// never strand a state file already written.
//
// Inside the DPAPI encryption the plaintext is
//
//	data key (32 bytes) || SHA-256(checkLabel || data key)[:16]
//
// because Microsoft documents that CryptUnprotectData may, for some
// corruptions, succeed with corrupted output; the check value makes such
// output an error here (the state file's AEAD would refuse it as well).

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/vettid/vettid-agent/internal/state"
)

const (
	// DPAPIName is the DPAPI protector's name in the state file header.
	DPAPIName = "dpapi"

	dpapiBlobVersion = 1
	// dpapiDescription is the description CryptProtectData stores, in
	// the clear, inside its blob.
	dpapiDescription = "vettid-agent data key"
	// dpapiEntropyLabel is the optional entropy given to DPAPI. It is a
	// public constant: it keeps this protector's blobs apart from other
	// programs' DPAPI blobs of the same user (a blob made by another
	// program does not open as this protector's key, nor the other way
	// round with a plain CryptUnprotectData call), and nothing more. Any
	// process running as the same user can call CryptUnprotectData with
	// it.
	dpapiEntropyLabel = "vettid-agent/protect/dpapi/v1\x00"
	dpapiCheckLabel   = "vettid-agent/protect/dpapi/v1 check\x00"
	dpapiCheckLen     = 16
	dpapiPlainLen     = state.DataKeyLen + dpapiCheckLen

	// maxDPAPIField bounds each variable-length field of the DPAPI blob,
	// and maxDPAPIBlob the whole wrapped key (the state file allows 4096
	// bytes for it).
	maxDPAPIField = 1024
	maxDPAPIBlob  = 4096

	// From wincrypt.h / dpapi.h.
	cryptprotectLocalMachine = 0x4
	calgAES128               = 0x660e
	calgAES192               = 0x660f
	calgAES256               = 0x6610
	calgSHA256               = 0x800c
	calgSHA384               = 0x800d
	calgSHA512               = 0x800e
)

// dpapiProvider is the DPAPI provider GUID
// {df9d8cd0-1501-11d1-8c7a-00c04fc297eb} in its in-memory byte order.
var dpapiProvider = []byte{0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb}

var (
	// ErrDPAPIBlobFormat: the wrapped key is not a DPAPI protector blob.
	ErrDPAPIBlobFormat = errors.New("the wrapped key is not in the DPAPI protector's format")
	// ErrDPAPIRefused: DPAPI found the blob invalid (ERROR_INVALID_DATA:
	// its integrity check failed, or other entropy), or what it returned
	// is not this protector's key.
	ErrDPAPIRefused = errors.New("Windows (DPAPI) does not open the state file's key: the file was altered, or its key was not made by this connector")
	// ErrDPAPIKeyLost: Windows could not use the user's DPAPI master key
	// the blob was made under (NTE_BAD_KEY_STATE): the master key is not
	// in this user's profile (another user, another computer, a
	// recreated profile), or it is there but cannot be decrypted (an
	// administrator reset the user's password).
	ErrDPAPIKeyLost = errors.New("Windows (DPAPI) could not use this user's key for the state file")
	// ErrDPAPIProfile: the user's profile or logon credentials are not
	// available to DPAPI in this logon (environmental, not definite).
	ErrDPAPIProfile = errors.New("Windows (DPAPI) cannot reach this user's keys in this logon: the user profile is not loaded or the logon has no password")
)

// dpapiInfo is what the format check reads from a DPAPI blob.
type dpapiInfo struct {
	masterKey [16]byte // the master key GUID, in-memory byte order
	flags     uint32
}

// masterKeyGUID formats the master key GUID as Windows names its file
// (lower-case, no braces).
func (i dpapiInfo) masterKeyGUID() string {
	g := i.masterKey
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(g[0:4]), binary.LittleEndian.Uint16(g[4:6]),
		binary.LittleEndian.Uint16(g[6:8]), g[8:10], g[10:16])
}

// dpapiDescriptionBytes is dpapiDescription as DPAPI stores it: UTF-16LE
// with a terminating NUL.
func dpapiDescriptionBytes() []byte {
	u := utf16.Encode([]rune(dpapiDescription + "\x00"))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}

// decodeDPAPIBlob checks this protector's version byte and the DPAPI
// blob's framing and fields, and returns the DPAPI part.
func decodeDPAPIBlob(blob []byte) ([]byte, dpapiInfo, error) {
	if len(blob) < 2 || len(blob) > maxDPAPIBlob || blob[0] != dpapiBlobVersion {
		return nil, dpapiInfo{}, ErrDPAPIBlobFormat
	}
	inner := blob[1:]
	info, err := checkDPAPIInner(inner)
	if err != nil {
		return nil, dpapiInfo{}, err
	}
	return inner, info, nil
}

func encodeDPAPIBlob(inner []byte) []byte {
	return append([]byte{dpapiBlobVersion}, inner...)
}

// checkDPAPIInner checks a DPAPI blob as CryptProtectData returns it.
func checkDPAPIInner(b []byte) (dpapiInfo, error) {
	var info dpapiInfo
	bad := ErrDPAPIBlobFormat
	r := b
	u32 := func() (uint32, bool) {
		if len(r) < 4 {
			return 0, false
		}
		v := binary.LittleEndian.Uint32(r)
		r = r[4:]
		return v, true
	}
	fixed := func(n int) ([]byte, bool) {
		if len(r) < n {
			return nil, false
		}
		p := r[:n]
		r = r[n:]
		return p, true
	}
	field := func(allowEmpty bool) ([]byte, bool) {
		n, ok := u32()
		if !ok || n > maxDPAPIField || (n == 0 && !allowEmpty) {
			return nil, false
		}
		return fixed(int(n))
	}
	if v, ok := u32(); !ok || v != 1 {
		return info, bad
	}
	if p, ok := fixed(16); !ok || !bytes.Equal(p, dpapiProvider) {
		return info, bad
	}
	if v, ok := u32(); !ok || v != 1 {
		return info, bad
	}
	mk, ok := fixed(16)
	if !ok {
		return info, bad
	}
	copy(info.masterKey[:], mk)
	if info.flags, ok = u32(); !ok || info.flags&cryptprotectLocalMachine != 0 {
		return info, bad
	}
	if d, ok := field(false); !ok || !bytes.Equal(d, dpapiDescriptionBytes()) {
		return info, bad
	}
	algCrypt, ok1 := u32()
	algCryptLen, ok2 := u32()
	if !ok1 || !ok2 {
		return info, bad
	}
	switch {
	case algCrypt == calgAES128 && algCryptLen == 128,
		algCrypt == calgAES192 && algCryptLen == 192,
		algCrypt == calgAES256 && algCryptLen == 256:
	default:
		return info, bad
	}
	if _, ok := field(false); !ok { // salt
		return info, bad
	}
	if _, ok := field(true); !ok { // HMAC key
		return info, bad
	}
	algHash, ok1 := u32()
	algHashLen, ok2 := u32()
	if !ok1 || !ok2 {
		return info, bad
	}
	switch {
	case algHash == calgSHA256 && algHashLen == 256,
		algHash == calgSHA384 && algHashLen == 384,
		algHash == calgSHA512 && algHashLen == 512:
	default:
		return info, bad
	}
	if _, ok := field(false); !ok { // second HMAC key (salt)
		return info, bad
	}
	if _, ok := field(false); !ok { // encrypted data
		return info, bad
	}
	if _, ok := field(false); !ok { // signature (HMAC)
		return info, bad
	}
	if len(r) != 0 {
		return info, bad
	}
	return info, nil
}

// dpapiPlaintext is what is given to CryptProtectData: the data key and
// its check value.
func dpapiPlaintext(dataKey []byte) []byte {
	out := make([]byte, 0, dpapiPlainLen)
	out = append(out, dataKey...)
	return append(out, dpapiCheck(dataKey)...)
}

func dpapiCheck(dataKey []byte) []byte {
	h := sha256.New()
	h.Write([]byte(dpapiCheckLabel))
	h.Write(dataKey)
	return h.Sum(nil)[:dpapiCheckLen]
}

// dpapiKeyFromPlaintext checks what CryptUnprotectData returned and
// returns a copy of the data key.
func dpapiKeyFromPlaintext(p []byte) ([]byte, error) {
	if len(p) != dpapiPlainLen {
		return nil, ErrDPAPIRefused
	}
	key, check := p[:state.DataKeyLen], p[state.DataKeyLen:]
	want := dpapiCheck(key)
	if subtle.ConstantTimeCompare(check, want) != 1 {
		return nil, ErrDPAPIRefused
	}
	return append([]byte(nil), key...), nil
}
