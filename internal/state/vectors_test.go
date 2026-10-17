package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The connector's own state file vectors (AGENT-PLAN §5,
// testdata/vectors/statefile.json). TestStateFileVectors regenerates the
// file from the fixed inputs below and compares it byte for byte; with
// -update it writes the file instead:
//
//	go test ./internal/state -run TestStateFileVectors -update
//
// A vector that stops matching is a stop-and-report item: a format
// change is a new header version, never an edit of these vectors.

var update = flag.Bool("update", false, "rewrite testdata/vectors/statefile.json")

var vectorPath = filepath.Join("..", "..", "testdata", "vectors", "statefile.json")
var sourcePath = filepath.Join("..", "..", "testdata", "vectors", "SOURCE.md")

type vectorCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Protector is "protector_key" or "other_protector_key": the test
	// protector key to open the file with.
	Protector string `json:"protector"`
	FileB64   string `json:"file_b64"`
	// Result is "ok", "format: <check>", "unknown_protector", "unwrap"
	// or "decrypt".
	Result string `json:"result"`
}

type vectorFile struct {
	Description          string       `json:"description"`
	Format               string       `json:"format"`
	ProtectorName        string       `json:"protector_name"`
	ProtectorWrap        string       `json:"protector_wrap"`
	ProtectorKeyHex      string       `json:"protector_key_hex"`
	OtherProtectorKeyHex string       `json:"other_protector_key_hex"`
	ProtectorNonceHex    string       `json:"protector_nonce_hex"`
	DataKeyHex           string       `json:"data_key_hex"`
	OtherDataKeyHex      string       `json:"other_data_key_hex"`
	NonceHex             string       `json:"nonce_hex"`
	CreatedAt            int64        `json:"created_at"`
	StateB64             string       `json:"state_b64"`
	Header               string       `json:"header"`
	Cases                []vectorCase `json:"cases"`
}

// Fixed, public test inputs. They protect nothing.
var (
	vecProtectorKey      = seq(0x40, 32)
	vecOtherProtectorKey = seq(0x80, 32)
	vecDataKey           = seq(0x00, 32)
	vecOtherDataKey      = seq(0x20, 32)
	vecNonce             = seq(0x60, 24)
	vecCreatedAt         = int64(1792195200) // 2026-10-17T00:00:00Z
	vecState             = []byte(`{"test":"state file vector; not a real device state"}`)
)

// frame builds a file from header bytes and a ciphertext, without any
// check, for the altered cases.
func frame(hb, ct []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(len(hb)))
	out = append(out, hb...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(ct)))
	return append(out, ct...)
}

func generateVectors(t *testing.T) []byte {
	t.Helper()
	p := newFixedProtector(vecProtectorKey)
	wrapped, err := p.Wrap(vecDataKey)
	if err != nil {
		t.Fatal(err)
	}
	h := &header{V: Version, Protector: p.Name(), WrappedKey: wrapped, Nonce: vecNonce, CreatedAt: vecCreatedAt}
	valid, err := encodeFile(h, vecDataKey, vecState)
	if err != nil {
		t.Fatal(err)
	}
	hb, ct, err := splitFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	hs := string(hb)

	// The header with one textual change, the same ciphertext.
	alter := func(old, new string) []byte {
		if !strings.Contains(hs, old) {
			t.Fatalf("header has no %q", old)
		}
		return frame([]byte(strings.Replace(hs, old, new, 1)), ct)
	}
	flipLast := append([]byte{}, valid...)
	flipLast[len(flipLast)-1] ^= 0x01

	// The data key under the other data key's wrapping: unwraps, then
	// does not decrypt.
	wrappedOther, err := p.Wrap(vecOtherDataKey)
	if err != nil {
		t.Fatal(err)
	}
	hOther := &header{V: Version, Protector: p.Name(), WrappedKey: wrappedOther, Nonce: vecNonce, CreatedAt: vecCreatedAt}
	hbOther, err := hOther.marshal()
	if err != nil {
		t.Fatal(err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(vecNonce)
	nonceAltered := append([]byte{}, vecNonce...)
	nonceAltered[0] ^= 0x01

	const pk, opk = "protector_key", "other_protector_key"
	cases := []vectorCase{
		{"valid", "a valid state file", pk, b64(valid), "ok"},
		{"wrong_protector_key", "the valid file, opened with a protector holding another key", opk, b64(valid), "unwrap"},
		{"wrong_data_key", "the header wraps another data key than the one the state is encrypted under", pk, b64(frame(hbOther, ct)), "decrypt"},
		{"tampered_header_created_at", "created_at changed by one second; still canonical", pk, b64(alter(`"created_at":1792195200`, `"created_at":1792195201`)), "decrypt"},
		{"tampered_header_nonce", "one bit of the nonce changed; still canonical", pk, b64(alter(nonceB64, base64.StdEncoding.EncodeToString(nonceAltered))), "decrypt"},
		{"tampered_header_whitespace", "a space added after the opening brace", pk, b64(alter(`{"v"`, `{ "v"`)), "format: header is not canonical"},
		{"tampered_header_member_case", "a member name in another case", pk, b64(alter(`"protector"`, `"Protector"`)), "format: header is not canonical"},
		{"tampered_header_duplicate_member", "created_at given twice", pk, b64(alter(`"created_at":1792195200`, `"created_at":1,"created_at":1792195200`)), "format: header is not canonical"},
		{"tampered_header_unknown_member", "an extra member", pk, b64(alter(`"created_at"`, `"x":1,"created_at"`)), "format: header members"},
		{"tampered_header_order", "two members swapped", pk, b64(alter(`{"v":1,"protector":"test-fixed"`, `{"protector":"test-fixed","v":1`)), "format: header is not canonical"},
		{"unknown_version", "v is 2", pk, b64(alter(`"v":1`, `"v":2`)), "format: unknown version"},
		{"unknown_protector", "a protector name this build does not know", pk, b64(alter(`"test-fixed"`, `"test-other"`)), "unknown_protector"},
		{"header_not_json", "the header is not JSON", pk, b64(frame([]byte("not json"), ct)), "format: header is not a JSON object"},
		{"header_length_zero", "header_len is 0", pk, b64(frame(nil, ct)), "format: header length"},
		{"truncated_empty", "an empty file", pk, b64(nil), "format: truncated"},
		{"truncated_length", "one byte", pk, b64(valid[:1]), "format: truncated"},
		{"truncated_header", "cut inside the header", pk, b64(valid[:2+len(hb)/2]), "format: truncated"},
		{"truncated_ct_len", "cut inside ct_len", pk, b64(valid[:2+len(hb)+2]), "format: truncated"},
		{"truncated_ciphertext", "the last byte removed", pk, b64(valid[:len(valid)-1]), "format: truncated"},
		{"trailing_bytes", "one byte appended", pk, b64(append(append([]byte{}, valid...), 0x00)), "format: trailing bytes"},
		{"tampered_ciphertext", "one bit of the tag changed", pk, b64(flipLast), "decrypt"},
	}

	v := vectorFile{
		Description: "VettID agent connector state file vectors (AGENT-PLAN §4.2, §5). Generated by " +
			"internal/state TestStateFileVectors from the fixed inputs below; public test values that protect nothing.",
		Format: "file = header_len (2, big-endian) || header (canonical JSON) || ct_len (4, big-endian) || ct; " +
			"ct = XChaCha20-Poly1305(data_key, header.nonce, aad = header bytes, state). See docs/STATE-FILE.md.",
		ProtectorName: testProtectorName,
		ProtectorWrap: "test only: wrapped_key = protector_nonce || XChaCha20-Poly1305(protector_key, protector_nonce, " +
			"aad = \"test-fixed\", data_key)",
		ProtectorKeyHex:      hex.EncodeToString(vecProtectorKey),
		OtherProtectorKeyHex: hex.EncodeToString(vecOtherProtectorKey),
		ProtectorNonceHex:    hex.EncodeToString(p.nonce),
		DataKeyHex:           hex.EncodeToString(vecDataKey),
		OtherDataKeyHex:      hex.EncodeToString(vecOtherDataKey),
		NonceHex:             hex.EncodeToString(vecNonce),
		CreatedAt:            vecCreatedAt,
		StateB64:             b64(vecState),
		Header:               hs,
		Cases:                cases,
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// resultOf names the outcome of decoding as a vector's result.
func resultOf(err error) string {
	var fe *FormatError
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &fe):
		return "format: " + fe.Check
	case errors.Is(err, ErrUnknownProtector):
		return "unknown_protector"
	case errors.Is(err, ErrUnwrap):
		return "unwrap"
	case errors.Is(err, ErrDecrypt):
		return "decrypt"
	default:
		return "other: " + err.Error()
	}
}

func TestStateFileVectors(t *testing.T) {
	gen := generateVectors(t)
	if *update {
		if err := os.WriteFile(vectorPath, gen, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s, sha256 %x; record it in testdata/vectors/SOURCE.md", vectorPath, sha256.Sum256(gen))
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, gen) {
		t.Fatal("statefile.json differs from what the generator produces: the format changed (stop and report)")
	}

	sum := hex.EncodeToString(func() []byte { s := sha256.Sum256(raw); return s[:] }())
	src, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "`statefile.json` | (generated here) | `"+sum+"`") {
		t.Errorf("testdata/vectors/SOURCE.md does not record statefile.json's sha256 %s", sum)
	}

	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	keys := map[string][]byte{
		"protector_key":       mustHexT(t, v.ProtectorKeyHex),
		"other_protector_key": mustHexT(t, v.OtherProtectorKeyHex),
	}
	state, _ := base64.StdEncoding.DecodeString(v.StateB64)
	secrets := [][]byte{mustHexT(t, v.DataKeyHex), mustHexT(t, v.OtherDataKeyHex), keys["protector_key"], state}
	seen := map[string]bool{}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			seen[c.Name] = true
			file, err := base64.StdEncoding.DecodeString(c.FileB64)
			if err != nil {
				t.Fatal(err)
			}
			key, ok := keys[c.Protector]
			if !ok {
				t.Fatalf("unknown protector key %q", c.Protector)
			}
			pt, _, _, dk, err := decodeFile(file, resolverFor(newFixedProtector(key)))
			if got := resultOf(err); got != c.Result {
				t.Fatalf("result %q, want %q", got, c.Result)
			}
			if err == nil {
				if !bytes.Equal(pt, state) {
					t.Error("decrypted state differs")
				}
				if !bytes.Equal(dk, secrets[0]) {
					t.Error("data key differs")
				}
				return
			}
			// Errors name the check, never the data.
			for _, s := range secrets {
				for _, form := range []string{string(s), hex.EncodeToString(s), b64(s)} {
					if strings.Contains(err.Error(), form) {
						t.Errorf("error %q carries secret material", err)
					}
				}
			}
		})
	}
	for _, want := range []string{"valid", "tampered_header_created_at", "wrong_protector_key", "wrong_data_key",
		"truncated_ciphertext", "trailing_bytes", "unknown_version", "unknown_protector"} {
		if !seen[want] {
			t.Errorf("vector case %s missing", want)
		}
	}
}

// The valid vector also loads through a Store from disk.
func TestStateFileVectorLoadsFromDisk(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	file, _ := base64.StdEncoding.DecodeString(v.Cases[0].FileB64)
	s := openTest(t)
	if err := writeAtomic(s.Dir(), s.Path(), file); err != nil {
		t.Fatal(err)
	}
	pt, err := s.Load(resolverFor(newFixedProtector(vecProtectorKey)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(pt, vecState) {
		t.Error("state differs")
	}
	if s.CreatedAt().Unix() != vecCreatedAt {
		t.Errorf("CreatedAt %v", s.CreatedAt())
	}
}

func mustHexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
