package protect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// dpapiFields are the fields of a synthetic DPAPI blob; tests change one
// at a time.
type dpapiFields struct {
	version, mkVersion uint32
	provider           []byte
	masterKey          []byte
	flags              uint32
	desc               []byte
	algCrypt, cryptLen uint32
	salt, hmacKey      []byte
	algHash, hashLen   uint32
	hmac2, data, sign  []byte
}

func goodDPAPIFields() dpapiFields {
	return dpapiFields{
		version: 1, mkVersion: 1, provider: dpapiProvider,
		masterKey: []byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x02, 0x03, 0x04},
		flags:     0, desc: dpapiDescriptionBytes(),
		algCrypt: calgAES256, cryptLen: 256, salt: bytes.Repeat([]byte{1}, 32),
		algHash: calgSHA512, hashLen: 512, hmac2: bytes.Repeat([]byte{2}, 32),
		data: bytes.Repeat([]byte{3}, 64), sign: bytes.Repeat([]byte{4}, 64),
	}
}

func (f dpapiFields) encode() []byte {
	le := binary.LittleEndian
	var b []byte
	lv := func(p []byte) { b = le.AppendUint32(b, uint32(len(p))); b = append(b, p...) }
	b = le.AppendUint32(b, f.version)
	b = append(b, f.provider...)
	b = le.AppendUint32(b, f.mkVersion)
	b = append(b, f.masterKey...)
	b = le.AppendUint32(b, f.flags)
	lv(f.desc)
	b = le.AppendUint32(b, f.algCrypt)
	b = le.AppendUint32(b, f.cryptLen)
	lv(f.salt)
	lv(f.hmacKey)
	b = le.AppendUint32(b, f.algHash)
	b = le.AppendUint32(b, f.hashLen)
	lv(f.hmac2)
	lv(f.data)
	lv(f.sign)
	return b
}

func TestDPAPIBlobFormat(t *testing.T) {
	good := encodeDPAPIBlob(goodDPAPIFields().encode())
	inner, info, err := decodeDPAPIBlob(good)
	if err != nil || !bytes.Equal(inner, good[1:]) {
		t.Fatalf("good blob: %v", err)
	}
	if g := info.masterKeyGUID(); g != "12345678-1234-5678-9abc-def001020304" {
		t.Errorf("master key GUID %s", g)
	}
	mod := func(f func(*dpapiFields)) []byte {
		x := goodDPAPIFields()
		f(&x)
		return encodeDPAPIBlob(x.encode())
	}
	otherDesc := dpapiDescriptionBytes()
	otherDesc[0] ^= 1
	cases := map[string][]byte{
		"empty":               nil,
		"version only":        {1},
		"our version 2":       append([]byte{2}, good[1:]...),
		"truncated":           good[:len(good)-1],
		"trailing":            append(append([]byte{}, good...), 0),
		"too long":            append(append([]byte{}, good...), make([]byte, maxDPAPIBlob)...),
		"DPAPI version 2":     mod(func(f *dpapiFields) { f.version = 2 }),
		"provider":            mod(func(f *dpapiFields) { f.provider = make([]byte, 16) }),
		"master key version":  mod(func(f *dpapiFields) { f.mkVersion = 2 }),
		"machine scope":       mod(func(f *dpapiFields) { f.flags = cryptprotectLocalMachine }),
		"UI flag stored":      mod(func(f *dpapiFields) { f.flags = 1 }),
		"system flag":         mod(func(f *dpapiFields) { f.flags = 0x20000000 }),
		"any other flag":      mod(func(f *dpapiFields) { f.flags = 0x80 }),
		"other description":   mod(func(f *dpapiFields) { f.desc = otherDesc }),
		"no description":      mod(func(f *dpapiFields) { f.desc = nil }),
		"3DES":                mod(func(f *dpapiFields) { f.algCrypt, f.cryptLen = 0x6603, 192 }),
		"AES-256 length":      mod(func(f *dpapiFields) { f.cryptLen = 128 }),
		"SHA-1":               mod(func(f *dpapiFields) { f.algHash, f.hashLen = 0x8004, 160 }),
		"no salt":             mod(func(f *dpapiFields) { f.salt = nil }),
		"no data":             mod(func(f *dpapiFields) { f.data = nil }),
		"no signature":        mod(func(f *dpapiFields) { f.sign = nil }),
		"field above maximum": mod(func(f *dpapiFields) { f.data = make([]byte, maxDPAPIField+1) }),
	}
	for name, b := range cases {
		if _, _, err := decodeDPAPIBlob(b); !errors.Is(err, ErrDPAPIBlobFormat) {
			t.Errorf("%s: %v, want ErrDPAPIBlobFormat", name, err)
		}
	}
	// A length field pointing past the end.
	huge := append([]byte{}, good...)
	binary.LittleEndian.PutUint32(huge[1+4+16+4+16+4:], 0xffffffff)
	if _, _, err := decodeDPAPIBlob(huge); !errors.Is(err, ErrDPAPIBlobFormat) {
		t.Errorf("huge length: %v", err)
	}
	// Other algorithm pairs Windows may be configured to use are fine.
	for _, f := range []func(*dpapiFields){
		func(f *dpapiFields) { f.algCrypt, f.cryptLen = calgAES128, 128 },
		func(f *dpapiFields) { f.algHash, f.hashLen = calgSHA256, 256 },
		func(f *dpapiFields) { f.hmacKey = []byte{9} },
	} {
		if _, _, err := decodeDPAPIBlob(mod(f)); err != nil {
			t.Errorf("accepted variant refused: %v", err)
		}
	}
}

func TestDPAPIPlaintextCheck(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	p := dpapiPlaintext(key)
	got, err := dpapiKeyFromPlaintext(p)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("round trip: %v", err)
	}
	for i := range p {
		q := append([]byte{}, p...)
		q[i] ^= 0x80
		if _, err := dpapiKeyFromPlaintext(q); !errors.Is(err, ErrDPAPIRefused) {
			t.Fatalf("byte %d flipped: %v", i, err)
		}
	}
	if _, err := dpapiKeyFromPlaintext(key); !errors.Is(err, ErrDPAPIRefused) {
		t.Fatalf("bare key: %v", err)
	}
}
