//go:build devstack

package devstack

// Unit tests of the relay mapping; they need no dev stack (CI runs them
// with -short).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testCA is a throwaway CA with a leaf for host.
type testCA struct {
	der  []byte
	leaf tls.Certificate
}

func newTestCA(t *testing.T, host string, isCA bool) *testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "devstack relay test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{der: caDER, leaf: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
}

func (c *testCA) b64() string { return base64.StdEncoding.EncodeToString(c.der) }

// front is a TLS front on the loopback interface serving c's leaf.
func front(t *testing.T, c *testCA) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "relay "+r.Host)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{c.leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func get(t *testing.T, hc *http.Client, u string) (string, error) {
	t.Helper()
	resp, err := hc.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

// TestRelayMapping: the relay origin is dialled at the TLS front and
// trusted under the stack's root; another host is refused before any
// connection, and a front whose certificate does not chain to the
// stack's root is refused (the system roots are not trusted).
func TestRelayMapping(t *testing.T) {
	ca := newTestCA(t, "relay.vettid.test", true)
	addr := front(t, ca)
	r, err := newRelay("https://relay.vettid.test", addr, ca.b64())
	if err != nil {
		t.Fatal(err)
	}
	if r.URL != "https://relay.vettid.test" {
		t.Errorf("URL %q", r.URL)
	}
	hc := r.HTTPClient()
	if body, err := get(t, hc, "https://relay.vettid.test/x"); err != nil || body != "relay relay.vettid.test" {
		t.Fatalf("mapped request: %q %v", body, err)
	}
	for _, u := range []string{"https://other.vettid.test/", "https://relay.vettid.test:8443/", "https://vettid.org/", "http://relay.vettid.test/"} {
		if _, err := get(t, hc, u); err == nil || !strings.Contains(err.Error(), "is not the dev stack's relay") {
			t.Errorf("%s: %v", u, err)
		}
	}
	other := newTestCA(t, "relay.vettid.test", true)
	r2, err := newRelay("https://relay.vettid.test", addr, other.b64())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, r2.HTTPClient(), "https://relay.vettid.test/x"); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("front under another root: %v", err)
	}
}

// TestRelayChecks: what the control port gives is checked.
func TestRelayChecks(t *testing.T) {
	ca := newTestCA(t, "relay.vettid.test", true)
	notCA := newTestCA(t, "relay.vettid.test", false)
	cases := []struct{ url, tls, root string }{
		{"http://relay.vettid.test", "127.0.0.1:1", ca.b64()},
		{"https://relay.vettid.org", "127.0.0.1:1", ca.b64()},
		{"https://relay.vettid.test:8443", "127.0.0.1:1", ca.b64()},
		{"https://relay.vettid.test/path", "127.0.0.1:1", ca.b64()},
		{"https://user@relay.vettid.test", "127.0.0.1:1", ca.b64()},
		{"https://.test", "127.0.0.1:1", ca.b64()},
		{"https://relay.vettid.test", "10.0.0.1:443", ca.b64()},
		{"https://relay.vettid.test", "relay.vettid.test:443", ca.b64()},
		{"https://relay.vettid.test", "127.0.0.1:0", ca.b64()},
		{"https://relay.vettid.test", "127.0.0.1:1", "not base64!"},
		{"https://relay.vettid.test", "127.0.0.1:1", base64.StdEncoding.EncodeToString([]byte("not a certificate"))},
		{"https://relay.vettid.test", "127.0.0.1:1", notCA.b64()},
	}
	for _, c := range cases {
		if _, err := newRelay(c.url, c.tls, c.root); err == nil {
			t.Errorf("accepted %q %q", c.url, c.tls)
		}
	}
	for _, ok := range [][2]string{{"https://relay.vettid.test", "127.0.0.1:18443"}, {"https://relay.vettid.test:443/", "[::1]:18443"}} {
		if _, err := newRelay(ok[0], ok[1], ca.b64()); err != nil {
			t.Errorf("refused %q %q: %v", ok[0], ok[1], err)
		}
	}
	for _, bad := range []string{"https://127.0.0.1:18082", "http://10.0.0.1:18082", "http://example.com:18082", "http://127.0.0.1", "http://127.0.0.1:18082/dev", "http://u@127.0.0.1:18082"} {
		if _, err := controlURL(bad); err == nil {
			t.Errorf("control URL %q accepted", bad)
		}
	}
	for _, good := range []string{"http://127.0.0.1:18082", "http://127.0.0.1:18082/", "http://localhost:18082", "http://[::1]:18082"} {
		if _, err := controlURL(good); err != nil {
			t.Errorf("control URL %q refused: %v", good, err)
		}
	}
}

// TestFetchRelay: FetchRelay reads /dev/trust and /dev/info of a control
// port; FromEnv does nothing without VETTID_AGENT_DEVSTACK.
func TestFetchRelay(t *testing.T) {
	ca := newTestCA(t, "relay.vettid.test", true)
	addr := front(t, ca)
	ctl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dev/trust":
			json.NewEncoder(w).Encode(map[string]any{"tls_root": ca.b64(), "relay_url": "https://relay.vettid.test"})
		case "/dev/info":
			json.NewEncoder(w).Encode(map[string]any{"relay_tls": addr})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ctl.Close()
	r, err := FetchRelay(context.Background(), ctl.URL)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := get(t, r.HTTPClient(), "https://relay.vettid.test/"); err != nil || body != "relay relay.vettid.test" {
		t.Fatalf("%q %v", body, err)
	}
	t.Setenv(EnvControl, "")
	if hc, err := FromEnv(context.Background()); hc != nil || err != nil {
		t.Errorf("FromEnv without %s: %v %v", EnvControl, hc, err)
	}
	t.Setenv(EnvControl, "http://"+ln(t))
	if _, err := FromEnv(context.Background()); err == nil {
		t.Error("FromEnv with nothing listening: no error")
	}
}

// ln returns a loopback address nothing listens on.
func ln(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
