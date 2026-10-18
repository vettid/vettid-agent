//go:build windows

package protect

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vettid/vettid-agent/internal/state"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, state.DataKeyLen) }

func TestDPAPIName(t *testing.T) {
	if NewDPAPI().Name() != "dpapi" || NewDPAPI().Wipe() != nil {
		t.Fatal("Name or Wipe")
	}
}

func TestDPAPIRoundTrip(t *testing.T) {
	p := NewDPAPI()
	key := testKey(0x5a)
	b1, err := p.Wrap(key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	b2, err := p.Wrap(key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Equal(b1, b2) {
		t.Error("two wraps of one key are equal")
	}
	if bytes.Contains(b1, key) || bytes.Contains(b1, key[:16]) {
		t.Error("the blob contains the key")
	}
	for _, b := range [][]byte{b1, b2} {
		got, err := p.Unwrap(b)
		if err != nil || !bytes.Equal(got, key) {
			t.Fatalf("Unwrap: %v", err)
		}
	}
	_, info, err := decodeDPAPIBlob(b1)
	if err != nil {
		t.Fatal(err)
	}
	inner := b1[1:]
	descLen := binary.LittleEndian.Uint32(inner[44:])
	algs := inner[48+descLen:]
	t.Logf("DPAPI blob: %d bytes, flags 0x%x, master key %s, crypt alg 0x%x/%d",
		len(b1), info.flags, info.masterKeyGUID(), binary.LittleEndian.Uint32(algs), binary.LittleEndian.Uint32(algs[4:]))
	if _, err := p.Wrap(key[:31]); err == nil {
		t.Error("short key wrapped")
	}
}

// Malformed blobs, and a well-formed machine-scope blob, are refused
// before Windows is asked.
func TestDPAPIRefusedBeforeWindows(t *testing.T) {
	// A real machine-scope blob with this protector's description.
	desc, _ := windows.UTF16PtrFromString(dpapiDescription)
	plain := dpapiPlaintext(testKey(1))
	var out windows.DataBlob
	if err := windows.CryptProtectData(dataBlob(plain), desc, dataBlob([]byte(dpapiEntropyLabel)), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &out); err != nil {
		t.Fatal(err)
	}
	machine := encodeDPAPIBlob(takeBlob(&out))

	called := 0
	orig := cryptUnprotect
	t.Cleanup(func() { cryptUnprotect = orig })
	cryptUnprotect = func(*windows.DataBlob, **uint16, *windows.DataBlob, uintptr, *windows.CryptProtectPromptStruct, uint32, *windows.DataBlob) error {
		called++
		return errors.New("must not be called")
	}
	good, err := NewDPAPI().Wrap(testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"machine scope": machine,
		"empty":         nil,
		"version 2":     append([]byte{2}, good[1:]...),
		"truncated":     good[:len(good)-1],
		"trailing":      append(append([]byte{}, good...), 0),
	} {
		if _, err := NewDPAPI().Unwrap(b); !errors.Is(err, ErrDPAPIBlobFormat) {
			t.Errorf("%s: %v, want ErrDPAPIBlobFormat", name, err)
		}
	}
	if called != 0 {
		t.Errorf("CryptUnprotectData called %d times for refused blobs", called)
	}
}

// A blob made with other entropy (another program's DPAPI blob of the
// same user) does not open.
func TestDPAPIOtherEntropyRefused(t *testing.T) {
	desc, _ := windows.UTF16PtrFromString(dpapiDescription)
	plain := dpapiPlaintext(testKey(3))
	for _, entropy := range [][]byte{nil, []byte("another program")} {
		var out windows.DataBlob
		if err := windows.CryptProtectData(dataBlob(plain), desc, dataBlob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
			t.Fatal(err)
		}
		b := encodeDPAPIBlob(takeBlob(&out))
		if _, err := NewDPAPI().Unwrap(b); !errors.Is(err, ErrDPAPIRefused) {
			t.Errorf("entropy %q: %v, want ErrDPAPIRefused", entropy, err)
		}
	}
}

// A blob with valid DPAPI protection whose plaintext is not this
// protector's (no check value) is refused.
func TestDPAPIBarePlaintextRefused(t *testing.T) {
	desc, _ := windows.UTF16PtrFromString(dpapiDescription)
	var out windows.DataBlob
	if err := windows.CryptProtectData(dataBlob(testKey(4)), desc, dataBlob([]byte(dpapiEntropyLabel)), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDPAPI().Unwrap(encodeDPAPIBlob(takeBlob(&out))); !errors.Is(err, ErrDPAPIRefused) {
		t.Errorf("bare key: %v, want ErrDPAPIRefused", err)
	}
}

// Every single-byte change of a real blob is refused, never opened;
// changes to the encrypted data and the signature are definite
// refusals. No error contains the blob.
func TestDPAPITamperedRefused(t *testing.T) {
	p := NewDPAPI()
	key := testKey(0x33)
	blob, err := p.Wrap(key)
	if err != nil {
		t.Fatal(err)
	}
	dataStart, signStart := locateDataSign(t, blob[1:])
	const mkStart = 4 + 16 + 4 // in the DPAPI part
	kinds := map[string]int{}
	for i := 1; i < len(blob); i++ {
		b := append([]byte{}, blob...)
		b[i] ^= 0x01
		got, err := p.Unwrap(b)
		if err == nil {
			t.Fatalf("byte %d changed: opened (key equal: %v)", i, bytes.Equal(got, key))
		}
		if strings.Contains(err.Error(), hex.EncodeToString(blob[len(blob)-16:])) {
			t.Fatalf("error contains blob bytes: %v", err)
		}
		pos := i - 1
		region := "header"
		if pos >= mkStart && pos < mkStart+16 {
			// Windows cannot find the master key: the message must name
			// alteration, not only another user or computer.
			if !errors.Is(err, ErrDPAPIKeyLost) || !strings.Contains(err.Error(), "altered or damaged") {
				t.Errorf("byte %d (master key GUID) changed: %v, want ErrDPAPIKeyLost naming alteration", i, err)
			}
			region = "master key GUID"
		}
		switch {
		case pos >= signStart:
			region = "signature"
		case pos >= dataStart && pos < signStart-4:
			region = "data"
		}
		if region != "header" && !errors.Is(err, ErrDPAPIRefused) {
			t.Errorf("byte %d (%s) changed: %v, want ErrDPAPIRefused", i, region, err)
		}
		kinds[fmt.Sprintf("%s: %s", region, errKind(err))]++
	}
	var ks []string
	for k, v := range kinds {
		ks = append(ks, fmt.Sprintf("%s ×%d", k, v))
	}
	sort.Strings(ks)
	t.Logf("tamper results: %s", strings.Join(ks, "; "))
}

func errKind(err error) string {
	for _, e := range []error{ErrDPAPIBlobFormat, ErrDPAPIRefused, ErrDPAPIKeyLost, ErrDPAPIProfile} {
		if errors.Is(err, e) {
			s := e.Error()
			var errno windows.Errno
			if errors.As(err, &errno) {
				s += fmt.Sprintf(" 0x%x", uint32(errno))
			}
			if i := strings.Index(err.Error(), "Windows error 0x"); i >= 0 {
				s = s[:min(len(s), 30)] + " [" + err.Error()[i:i+26] + "]"
			} else {
				s = s[:min(len(s), 30)]
			}
			return s
		}
	}
	return "other: " + err.Error()
}

// locateDataSign returns the offsets of the encrypted data's and the
// signature's contents (after their length fields) in a DPAPI blob.
func locateDataSign(t *testing.T, b []byte) (int, int) {
	t.Helper()
	le := binary.LittleEndian
	off := 4 + 16 + 4 + 16 + 4
	skip := func() int { n := int(le.Uint32(b[off:])); off += 4; start := off; off += n; return start }
	skip()   // description
	off += 8 // algCrypt, len
	skip()   // salt
	skip()   // hmac key
	off += 8 // algHash, len
	skip()   // hmac2
	data := skip()
	sign := skip()
	if off != len(b) {
		t.Fatalf("layout walk ended at %d of %d", off, len(b))
	}
	return data, sign
}

func TestClassifyDPAPI(t *testing.T) {
	cases := []struct {
		code uint32
		want error
	}{
		{uint32(windows.ERROR_INVALID_DATA), ErrDPAPIRefused},
		{uint32(windows.NTE_BAD_DATA), ErrDPAPIRefused},
		{uint32(windows.ERROR_PASSWORD_RESTRICTION), ErrDPAPIRefused},
		{uint32(windows.NTE_BAD_KEY_STATE), ErrDPAPIKeyLost},
		{uint32(windows.ERROR_FILE_NOT_FOUND), ErrDPAPIProfile},
		{uint32(windows.ERROR_PATH_NOT_FOUND), ErrDPAPIProfile},
		{uint32(windows.ERROR_NO_SUCH_LOGON_SESSION), ErrDPAPIProfile},
		{uint32(windows.ERROR_NOT_FOUND), ErrDPAPIProfile},
		{uint32(windows.ERROR_ACCESS_DENIED), nil},
	}
	all := []error{ErrDPAPIRefused, ErrDPAPIKeyLost, ErrDPAPIProfile}
	for _, c := range cases {
		err := classifyDPAPI("open the key", windows.Errno(c.code), nil)
		for _, e := range all {
			if errors.Is(err, e) != (e == c.want) {
				t.Errorf("0x%x: %v", c.code, err)
			}
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("0x%08X", c.code)) {
			t.Errorf("0x%x: code missing in %q", c.code, err)
		}
	}
	// Only the lost key's hint mentions another computer, as one
	// possibility next to alteration, and it asks to check before
	// pairing again.
	if strings.Contains(classifyDPAPI("x", windows.ERROR_INVALID_DATA, nil).Error(), "computer") {
		t.Error("ERROR_INVALID_DATA claims another computer")
	}
	if s := classifyDPAPI("x", windows.ERROR_FILE_NOT_FOUND, nil).Error(); strings.Contains(s, "another") {
		t.Errorf("profile error claims another user or computer: %s", s)
	}
	s := classifyDPAPI("x", windows.Errno(windows.NTE_BAD_KEY_STATE), nil).Error()
	if !strings.Contains(s, "altered or damaged") || !strings.Contains(s, "domain reachable") ||
		strings.Index(s, "check first") > strings.Index(s, "pair again") {
		t.Errorf("lost key, unknown cause: %s", s)
	}
	// Wrap's errors never speak of a state file or another user.
	for _, code := range []windows.Errno{windows.Errno(windows.NTE_BAD_KEY_STATE), windows.ERROR_INVALID_DATA, windows.ERROR_ACCESS_DENIED} {
		s := classifyProtect(code).Error()
		if strings.Contains(s, "state file") || strings.Contains(s, "another") || strings.Contains(s, "altered") {
			t.Errorf("Wrap error 0x%x: %s", uint32(code), s)
		}
	}
	if !errors.Is(classifyProtect(windows.ERROR_FILE_NOT_FOUND), ErrDPAPIProfile) {
		t.Error("Wrap without a profile is not ErrDPAPIProfile")
	}
}

// The hint for NTE_BAD_KEY_STATE follows whether the master key file is
// in this user's profile.
func TestDPAPIKeyLostHint(t *testing.T) {
	blob, err := NewDPAPI().Wrap(testKey(5))
	if err != nil {
		t.Fatal(err)
	}
	_, info, _ := decodeDPAPIBlob(blob)
	if masterKeyPresent(info) != 1 {
		t.Fatalf("the master key %s of a fresh blob is not found in this profile", info.masterKeyGUID())
	}
	if h := keyLostHint(&info); !strings.Contains(h, "administrator reset") || strings.Contains(h, "another computer") {
		t.Errorf("present key hint: %s", h)
	}
	info.masterKey[0] ^= 0xff
	if masterKeyPresent(info) != 0 {
		t.Fatal("an unknown master key reported present")
	}
	if h := keyLostHint(&info); !strings.Contains(h, "another Windows user") || !strings.Contains(h, "altered or damaged") || strings.Contains(h, "administrator") {
		t.Errorf("absent key hint: %s", h)
	}
}

// The decrypted buffer is zeroed before it is freed.
func TestDPAPITakeBlobZeroes(t *testing.T) {
	var out windows.DataBlob
	desc, _ := windows.UTF16PtrFromString("t")
	if err := windows.CryptProtectData(dataBlob([]byte("abc")), desc, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		t.Fatal(err)
	}
	var seen []byte
	orig := freeHook
	t.Cleanup(func() { freeHook = orig })
	freeHook = func(p *byte, n uint32) { seen = append([]byte{}, unsafe.Slice(p, n)...) }
	got := takeBlob(&out)
	if len(got) == 0 || len(seen) != len(got) || !bytes.Equal(seen, make([]byte, len(got))) {
		t.Fatalf("buffer not zeroed before LocalFree: %x", seen)
	}
	if out.Data != nil || out.Size != 0 {
		t.Error("blob not reset")
	}
}

// A state file created with the DPAPI protector reopens; Wipe succeeds.
func TestDPAPIStateFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Create(NewDPAPI(), []byte("device state")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	s.Close()
	s, err = state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	resolve := func(name string) state.Protector {
		if name == DPAPIName {
			return NewDPAPI()
		}
		return nil
	}
	got, err := s.Load(resolve)
	if err != nil || string(got) != "device state" {
		t.Fatalf("Load = %q, %v", got, err)
	}
	if err := s.Wipe(nil); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
}

type fakeProbe struct {
	wrapErr, unwrapErr error
	wrong              bool
}

func (f fakeProbe) Wrap(k []byte) ([]byte, error) { return append([]byte{}, k...), f.wrapErr }
func (f fakeProbe) Unwrap(b []byte) ([]byte, error) {
	if f.wrong {
		b = append([]byte{}, b...)
		b[0] ^= 1
	}
	return b, f.unwrapErr
}

func TestChooseProtectorWindows(t *testing.T) {
	c, err := ChooseProtector(ChooseOptions{})
	if err != nil || c.Protector != DPAPIName || !c.MachineBound || c.Notice() != "" {
		t.Fatalf("choice %+v, %v", c, err)
	}
	orig := dpapiProbe
	t.Cleanup(func() { dpapiProbe = orig })
	profileErr := classifyProtect(windows.ERROR_FILE_NOT_FOUND)
	for name, f := range map[string]fakeProbe{
		"wrap fails":   {wrapErr: profileErr},
		"unwrap fails": {unwrapErr: ErrDPAPIRefused},
		"wrong key":    {wrong: true},
	} {
		dpapiProbe = func() probeProtector { return f }
		c, err := ChooseProtector(ChooseOptions{})
		if err == nil || !strings.Contains(err.Error(), "choose a passphrase") {
			t.Errorf("%s: %+v, %v", name, c, err)
		}
		if f.wrapErr != nil && !errors.Is(err, ErrDPAPIProfile) {
			t.Errorf("%s: cause lost: %v", name, err)
		}
		c, err = ChooseProtector(ChooseOptions{AllowPassphraseFallback: true})
		if err != nil || c.Protector != PassphraseName || c.MachineBound || !strings.Contains(c.Reason, "DPAPI") {
			t.Errorf("%s with fallback: %+v, %v", name, c, err)
		}
	}
}
