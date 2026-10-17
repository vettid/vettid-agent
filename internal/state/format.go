package state

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/chacha20poly1305"
)

// The state file format (AGENT-PLAN §4.2; docs/STATE-FILE.md):
//
//	file   = header_len || header || ct_len || ct
//	header_len : 2 bytes, big-endian, 1..MaxHeaderLen
//	header     : header_len bytes, the canonical JSON header (below)
//	ct_len     : 4 bytes, big-endian, Overhead..MaxStateLen+Overhead
//	ct         : ct_len bytes,
//	             XChaCha20-Poly1305(key = data key, nonce = header.nonce,
//	                                aad = header (the exact bytes), state)
//
// and nothing after ct. The header is the JSON object
//
//	{"v":1,"protector":"<name>","wrapped_key":"<base64>","nonce":"<base64>","created_at":<unix seconds>}
//
// with exactly these members, in this order, no white space, standard
// base64 with padding, as encoding/json writes the header struct below.
// A header that is not byte-for-byte that canonical encoding of its own
// values is refused, so there is one encoding per header and nothing
// in it goes unauthenticated by a quirk of the JSON parser (duplicate
// or case-folded member names, unknown members).

const (
	// Version is the only header version this package reads or writes.
	Version = 1

	// MaxHeaderLen bounds the header.
	MaxHeaderLen = 8192
	// MaxWrappedKeyLen bounds a protector's wrapped data key.
	MaxWrappedKeyLen = 4096
	// MaxStateLen bounds the plaintext state (the client's Save output
	// is a few kilobytes).
	MaxStateLen = 16 << 20

	// DataKeyLen is the length of the data key (256 bits).
	DataKeyLen = chacha20poly1305.KeySize
	// NonceLen is the XChaCha20-Poly1305 nonce length.
	NonceLen = chacha20poly1305.NonceSizeX
	// Overhead is the AEAD tag length.
	Overhead = chacha20poly1305.Overhead

	maxFileLen = 2 + MaxHeaderLen + 4 + MaxStateLen + Overhead
)

// protectorName is the form of a protector's name in the header.
var protectorName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// header is the state file's header. Field order is the canonical
// member order; json.Marshal writes []byte as standard padded base64.
type header struct {
	V          int    `json:"v"`
	Protector  string `json:"protector"`
	WrappedKey []byte `json:"wrapped_key"`
	Nonce      []byte `json:"nonce"`
	CreatedAt  int64  `json:"created_at"`
}

func (h *header) validate() error {
	if h.V != Version {
		return formatErr("unknown version")
	}
	if !protectorName.MatchString(h.Protector) {
		return formatErr("protector name")
	}
	if len(h.WrappedKey) == 0 || len(h.WrappedKey) > MaxWrappedKeyLen {
		return formatErr("wrapped key length")
	}
	if len(h.Nonce) != NonceLen {
		return formatErr("nonce length")
	}
	if h.CreatedAt <= 0 {
		return formatErr("created_at")
	}
	return nil
}

func (h *header) marshal() ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxHeaderLen {
		return nil, formatErr("header length")
	}
	return b, nil
}

// parseHeader decodes a header and refuses anything but the canonical
// encoding of a valid header.
func parseHeader(b []byte) (*header, error) {
	// The version first, so that a later format is reported as such.
	var probe struct {
		V json.RawMessage `json:"v"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return nil, formatErr("header is not a JSON object")
	}
	if string(probe.V) != "1" {
		return nil, formatErr("unknown version")
	}
	var h header
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, formatErr("header members")
	}
	if dec.More() {
		return nil, formatErr("header members")
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	canon, err := json.Marshal(&h)
	if err != nil || !bytes.Equal(canon, b) {
		return nil, formatErr("header is not canonical")
	}
	return &h, nil
}

// encodeFile builds a state file. h.Nonce is the AEAD nonce; callers
// other than the vector generator pass a fresh random one.
func encodeFile(h *header, dataKey, plaintext []byte) ([]byte, error) {
	if len(dataKey) != DataKeyLen {
		return nil, errors.New("state: data key length")
	}
	if len(plaintext) > MaxStateLen {
		return nil, errors.New("state: state too large")
	}
	hb, err := h.marshal()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(hb)+4+len(plaintext)+Overhead)
	out = binary.BigEndian.AppendUint16(out, uint16(len(hb)))
	out = append(out, hb...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(plaintext)+Overhead))
	out = aead.Seal(out, h.Nonce, plaintext, hb)
	return out, nil
}

// splitFile checks the framing and returns the header bytes and the
// ciphertext.
func splitFile(raw []byte) (hb, ct []byte, err error) {
	if len(raw) < 2 {
		return nil, nil, formatErr("truncated")
	}
	hlen := int(binary.BigEndian.Uint16(raw))
	if hlen == 0 || hlen > MaxHeaderLen {
		return nil, nil, formatErr("header length")
	}
	if len(raw) < 2+hlen+4 {
		return nil, nil, formatErr("truncated")
	}
	hb = raw[2 : 2+hlen]
	clen := uint64(binary.BigEndian.Uint32(raw[2+hlen:]))
	if clen < Overhead || clen > MaxStateLen+Overhead {
		return nil, nil, formatErr("ciphertext length")
	}
	rest := uint64(len(raw) - (2 + hlen + 4))
	switch {
	case rest < clen:
		return nil, nil, formatErr("truncated")
	case rest > clen:
		return nil, nil, formatErr("trailing bytes")
	}
	return hb, raw[2+hlen+4:], nil
}

// decodeFile checks and opens a state file. On success it returns the
// plaintext, the header, the protector that unwrapped the data key and
// the data key, which the caller must clear when done with it.
func decodeFile(raw []byte, resolve Resolver) (plaintext []byte, h *header, p Protector, dataKey []byte, err error) {
	hb, ct, err := splitFile(raw)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	h, err = parseHeader(hb)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if resolve == nil {
		return nil, nil, nil, nil, ErrUnknownProtector
	}
	p = resolve(h.Protector)
	if p == nil || p.Name() != h.Protector {
		return nil, nil, nil, nil, ErrUnknownProtector
	}
	dataKey, err = p.Unwrap(h.WrappedKey)
	if err != nil {
		// The protector's error says which of its checks failed; it
		// never carries key material (Protector contract).
		return nil, nil, nil, nil, fmt.Errorf("%w: %w", ErrUnwrap, err)
	}
	if len(dataKey) != DataKeyLen {
		clear(dataKey)
		return nil, nil, nil, nil, fmt.Errorf("%w: data key length", ErrUnwrap)
	}
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		clear(dataKey)
		return nil, nil, nil, nil, err
	}
	plaintext, err = aead.Open(nil, h.Nonce, ct, hb)
	if err != nil {
		clear(dataKey)
		return nil, nil, nil, nil, ErrDecrypt
	}
	return plaintext, h, p, dataKey, nil
}

// FormatError is a state file that does not have the format of
// docs/STATE-FILE.md. Check names the check that failed.
type FormatError struct{ Check string }

func (e *FormatError) Error() string { return "state file format: " + e.Check }

// Is makes errors.Is(err, ErrFormat) true for every FormatError.
func (e *FormatError) Is(target error) bool { return target == ErrFormat }

func formatErr(check string) error { return &FormatError{Check: check} }
