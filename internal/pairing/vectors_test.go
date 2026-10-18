package pairing

// The vault's invite.json and handshake.json vectors (VAULT-MESSAGING
// §16; AGENT-PLAN §5), copied from vettid-vault at the commit recorded
// in testdata/vectors/SOURCE.md. A vector that stops matching is a
// stop-and-report item: never edit testdata/vectors/ or skip a case to
// make this pass.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The sha256sums recorded in testdata/vectors/SOURCE.md.
const (
	inviteVectorSHA256    = "6d7be9ba65f8426070ee54f0ea6ed84fed1e49c54eb31e09a1e177d3d5286d2f"
	handshakeVectorSHA256 = "9b69503b507fd117ab3d6a66368cb60bb24e09286867921a6f473fb476fb0577"
)

func loadVector(t *testing.T, name, sum string) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != sum {
		t.Fatalf("%s: sha256 %x does not match testdata/vectors/SOURCE.md (stop and report; never edit the vector)", name, got)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func vstr(t *testing.T, m map[string]json.RawMessage, k string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(m[k], &s); err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return s
}

func vhex(t *testing.T, m map[string]json.RawMessage, k string) []byte {
	t.Helper()
	b, err := hex.DecodeString(vstr(t, m, k))
	if err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return b
}

func vb64(t *testing.T, m map[string]json.RawMessage, k string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(vstr(t, m, k))
	if err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return b
}

// TestInviteVector: the code forms of §6.4 find the vector's payload;
// its `t` ("c") is refused as not an agent code; the same QR as an agent
// code passes before `e` and is refused from `e` on; the bundle opens
// against `h` and an altered blob is refused by the hash check before
// anything is decrypted.
func TestInviteVector(t *testing.T) {
	m := loadVector(t, "invite.json", inviteVectorSHA256)
	link := vstr(t, m, "link")
	now, err := time.Parse(time.RFC3339, vstr(t, m, "now"))
	if err != nil {
		t.Fatal(err)
	}
	q, err := invite.ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := q.Marshal(); string(b) != vstr(t, m, "qr_json") {
		t.Fatalf("the link does not decode to qr_json")
	}

	forms := map[string]string{
		"bare":            link,
		"bare with space": "  " + link + "\r\n",
		"url":             q.Relay + "/connect#" + link,
		"url other host":  "https://relay.example.net/connect#" + link,
		"vettid scheme":   "vettid://connect#" + link,
		"in text":         "Here is the code: <https://relay.vettid.org/connect#" + link + ">. It expires soon.",
		"twice":           link + " and again vettid://connect#" + link,
	}
	for name, text := range forms {
		got, gq, err := findPayload(text)
		if err != nil || got != link || gq.Relay != "https://relay.vettid.org" {
			t.Errorf("%s: got %v, relay %v", name, err, gq)
		}
		if _, err := ParseCode(text, now); !errors.Is(err, ErrNotAgent) {
			t.Errorf("%s: kind c: got %v, want ErrNotAgent", name, err)
		} else if strings.Contains(err.Error(), link) {
			t.Errorf("%s: the error contains the code", name)
		}
	}
	for name, text := range map[string]string{
		"empty":     "",
		"truncated": link[:len(link)-4],
		"altered":   link[:40] + "A" + link[41:],
		"words":     "no code here at all, only words",
	} {
		if _, _, err := findPayload(text); err == nil {
			t.Errorf("%s: found a payload", name)
		}
	}
	other := *q
	other.ClaimID = strings.Repeat("b", invite.ClaimIDLen)
	otherLink, err := other.Link()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := findPayload(link + " " + otherLink); !errors.Is(err, ErrManyCodes) {
		t.Errorf("two codes: got %v", err)
	}
	if _, err := ParseCode(strings.Repeat(" ", MaxCodeInput+1), now); !errors.Is(err, ErrCodeTooLong) {
		t.Errorf("too long: got %v", err)
	}

	// The same QR as an agent code: the expiry check.
	agent := *q
	agent.Kind = invite.KindAgent
	agentLink, err := agent.Link()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Unix(q.Exp, 0)
	for _, tc := range []struct {
		at   time.Time
		want error
	}{{now, nil}, {exp.Add(-time.Second), nil}, {exp, ErrCodeExpired}, {exp.Add(time.Hour), ErrCodeExpired}} {
		c, err := ParseCode(agentLink, tc.at)
		if !errors.Is(err, tc.want) {
			t.Errorf("at %v: got %v, want %v", tc.at, err, tc.want)
			continue
		}
		if err == nil && (c.Link != agentLink || c.Relay != q.Relay || !c.Exp.Equal(exp)) {
			t.Errorf("at %v: got %+v", tc.at, c)
		}
	}

	// The hash commitment, as the client checks it when it fetches the
	// claim (invite.OpenBundle, §6.4).
	blob := vb64(t, m, "blob_b64")
	if h := sha256.Sum256(blob); !bytes.Equal(h[:], vhex(t, m, "h_hex")) || !bytes.Equal(h[:], q.Hash[:]) {
		t.Fatal("h does not match the blob")
	}
	b, err := invite.OpenBundle(blob, q, now)
	if err != nil {
		t.Fatal(err)
	}
	if bj, _ := b.Marshal(); string(bj) != vstr(t, m, "bundle_json") {
		t.Error("the bundle does not round-trip to bundle_json")
	}
	for _, i := range []int{0, len(blob) / 2, len(blob) - 1} {
		alt := append([]byte(nil), blob...)
		alt[i] ^= 1
		if _, err := invite.OpenBundle(alt, q, now); !errors.Is(err, invite.ErrHash) {
			t.Errorf("blob altered at %d: got %v, want ErrHash", i, err)
		}
	}
	if _, err := invite.OpenBundle(blob, q, exp); !errors.Is(err, invite.ErrExpired) {
		t.Errorf("at e: got %v, want ErrExpired", err)
	}
	if _, err := invite.OpenBundle(blob, &agent, now); !errors.Is(err, invite.ErrKind) {
		t.Errorf("agent QR over a connection bundle: got %v, want ErrKind", err)
	}
}

// TestHandshakeVector: from the initiator's side, through the imported
// handshake package, the vector's hs.resp opens under the ephemeral key,
// the transcript and key schedule give the vector's prk, hs.fin opens
// with k_i2r and reveals n_I, and the SAS shown is the vector's
// ("564218" shown as "564 218").
func TestHandshakeVector(t *testing.T) {
	m := loadVector(t, "handshake.json", handshakeVectorSHA256)
	var in map[string]json.RawMessage
	if err := json.Unmarshal(m["inputs"], &in); err != nil {
		t.Fatal(err)
	}
	envInit := vb64(t, m, "hs_init_envelope_b64")
	envResp := vb64(t, m, "hs_resp_envelope_b64")
	envFin := vb64(t, m, "hs_fin_envelope_b64")

	eph, err := suite.NewPrivateKey(vhex(t, in, "initiator_eph_seed_hex"))
	if err != nil {
		t.Fatal(err)
	}
	re, err := envelope.Parse(envResp)
	if err != nil {
		t.Fatal(err)
	}
	rpad, rexp, err := envelope.OpenSealed(re, eph)
	if err != nil {
		t.Fatal(err)
	}
	ke, err := rexp.Export("vettid/vms/2/hs-ke", 32)
	if err != nil || !bytes.Equal(ke, vhex(t, m, "K_e_hex")) {
		t.Fatalf("K_e: %v", err)
	}
	rin, err := envelope.DecodeInner(rpad, envelope.ModeSealed)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := handshake.ParseResp(rin.Body, handshake.PurposeConnection)
	if err != nil {
		t.Fatal(err)
	}
	nR := vhex(t, in, "n_R_hex")
	if !bytes.Equal(resp.SASNonce, nR) {
		t.Fatal("n_R")
	}
	th1 := handshake.Th1(envInit)
	th := handshake.Th(envInit, envResp[:1140])
	if !bytes.Equal(th1[:], vhex(t, m, "th1_hex")) || !bytes.Equal(th[:], vhex(t, m, "th_hex")) {
		t.Fatal("transcript hashes")
	}
	sc, err := handshake.DeriveSchedule(vhex(t, m, "K_s_hex"), ke, th1, th)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sc.PRK, vhex(t, m, "prk_hex")) {
		t.Fatal("prk")
	}
	fe, err := envelope.Parse(envFin)
	if err != nil {
		t.Fatal(err)
	}
	fpad, err := envelope.OpenSession(fe, sc.KI2R)
	if err != nil {
		t.Fatal(err)
	}
	fin, err := envelope.DecodeInner(fpad, envelope.ModeSession)
	if err != nil {
		t.Fatal(err)
	}
	f, err := handshake.ParseFin(fin.Body, handshake.PurposeConnection)
	if err != nil {
		t.Fatal(err)
	}
	nI := vhex(t, in, "n_I_hex")
	if !bytes.Equal(f.SASNonce, nI) || !handshake.CheckSASCommit(vhex(t, m, "sas_commit_hex"), nI) {
		t.Fatal("n_I or its commitment")
	}
	sas, err := handshake.SAS(sc.PRK, th, nI, nR)
	if err != nil || sas != vstr(t, m, "sas") {
		t.Fatalf("SAS %q (%v), want the vector's", sas, err)
	}
	shown, err := FormatSAS(sas)
	if err != nil || shown != "564 218" {
		t.Fatalf("shown %q (%v)", shown, err)
	}
}

func TestFormatSAS(t *testing.T) {
	for in, want := range map[string]string{"000000": "000 000", "123456": "123 456", "999999": "999 999"} {
		if got, err := FormatSAS(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", "١٢٣٤٥٦", "123 45"} {
		if _, err := FormatSAS(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
