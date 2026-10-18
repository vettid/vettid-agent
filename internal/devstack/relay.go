//go:build devstack

package devstack

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

// EnvControl names the dev stack's control port (for example
// `http://127.0.0.1:18082`, `ctl` in its ready.json) for a devstack build
// of the connector: relay requests then go to that stack's relay.
const EnvControl = "VETTID_AGENT_DEVSTACK"

// Bounds of the control port's answers.
const (
	maxControlAnswer = 1 << 20
	controlTimeout   = 15 * time.Second
	// relayTimeout is the vault client's default (client.Config.HTTP).
	relayTimeout = 60 * time.Second
)

// Relay is the dev stack's relay as the connector reaches it: the origin
// its tokens and pairing codes name, dialled at the stack's TLS front,
// with the stack's TEST TLS root as the only trusted root.
type Relay struct {
	// URL is the origin the stack's tokens name (`https://relay.vettid.test`).
	URL string
	// hostPort is URL's host with port 443: the one address mapped.
	hostPort string
	// dial is the TLS front's loopback address (`relay_tls`).
	dial  string
	roots *x509.CertPool
}

// FromEnv returns the relay HTTP client of the dev stack that
// EnvControl names, or nil if EnvControl is not set.
func FromEnv(ctx context.Context) (*http.Client, error) {
	ctl := os.Getenv(EnvControl)
	if ctl == "" {
		return nil, nil
	}
	r, err := FetchRelay(ctx, ctl)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvControl, err)
	}
	return r.HTTPClient(), nil
}

// FetchRelay reads the relay's origin and test root from the dev stack's
// control port ctl (`GET /dev/trust`) and its TLS front (`GET /dev/info`,
// `relay_tls`). ctl and the TLS front must be on the loopback interface,
// and the origin an https origin under the reserved `.test` domain
// (RFC 6761), so that the mapping can never send a relay request to a
// real service.
func FetchRelay(ctx context.Context, ctl string) (*Relay, error) {
	base, err := controlURL(ctl)
	if err != nil {
		return nil, err
	}
	hc := &http.Client{
		Timeout:       controlTimeout,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	var trust struct {
		TLSRoot  string `json:"tls_root"`
		RelayURL string `json:"relay_url"`
	}
	if err := getJSON(ctx, hc, base+"/dev/trust", &trust); err != nil {
		return nil, err
	}
	var info struct {
		RelayTLS string `json:"relay_tls"`
	}
	if err := getJSON(ctx, hc, base+"/dev/info", &info); err != nil {
		return nil, err
	}
	return newRelay(trust.RelayURL, info.RelayTLS, trust.TLSRoot)
}

// newRelay checks what the control port gave.
func newRelay(relayURL, relayTLS, tlsRoot string) (*Relay, error) {
	u, err := url.Parse(relayURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("the dev stack's relay_url is not an https origin")
	}
	host := u.Hostname()
	if p := u.Port(); p != "" && p != "443" {
		return nil, errors.New("the dev stack's relay_url names a port other than 443")
	}
	if !strings.HasSuffix(host, ".test") || strings.Trim(host, ".") != host || len(host) <= len(".test") {
		return nil, fmt.Errorf("the dev stack's relay_url host %q is not under the reserved .test domain", host)
	}
	ap, err := netip.ParseAddrPort(relayTLS)
	if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
		return nil, fmt.Errorf("the dev stack's relay_tls %q is not a loopback address and port", relayTLS)
	}
	der, err := base64.StdEncoding.DecodeString(tlsRoot)
	if err != nil || len(der) == 0 {
		return nil, errors.New("the dev stack's tls_root is not base64")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("the dev stack's tls_root: %w", err)
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("the dev stack's tls_root is not a CA certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &Relay{URL: "https://" + host, hostPort: net.JoinHostPort(host, "443"), dial: ap.String(), roots: roots}, nil
}

// controlURL checks ctl: plain HTTP to a loopback address, no path.
func controlURL(ctl string) (string, error) {
	u, err := url.Parse(strings.TrimRight(ctl, "/"))
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the control URL must be http://<loopback address>:<port>")
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if u.Hostname() == "localhost" {
		ip, err = netip.MustParseAddr("127.0.0.1"), nil
		u.Host = net.JoinHostPort("127.0.0.1", u.Port())
	}
	if err != nil || !ip.IsLoopback() || u.Port() == "" {
		return "", errors.New("the control URL must be http://<loopback address>:<port>")
	}
	return u.String(), nil
}

func getJSON(ctx context.Context, hc *http.Client, u string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, controlTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("the dev stack's control port: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxControlAnswer+1))
	if err != nil {
		return fmt.Errorf("the dev stack's control port: %w", err)
	}
	if resp.StatusCode != http.StatusOK || len(b) > maxControlAnswer {
		return fmt.Errorf("the dev stack's control port answered HTTP %d (%d bytes)", resp.StatusCode, len(b))
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("the dev stack's control port: %w", err)
	}
	return nil
}

// HTTPClient is the connector's relay client for the dev stack: a
// connection to the relay's origin (host and port 443) is dialled at the
// stack's TLS front, and any other address is refused; the server must
// present a certificate for the origin's host that chains to the stack's
// TEST TLS root, which is the only root trusted (not the system's). No
// proxy, and no redirects followed.
func (r *Relay) HTTPClient() *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != r.hostPort {
				return nil, fmt.Errorf("devstack build: %s is not the dev stack's relay (%s)", addr, r.hostPort)
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", r.dial)
		},
		TLSClientConfig:     &tls.Config{RootCAs: r.roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        8,
	}
	return &http.Client{
		Transport:     tr,
		Timeout:       relayTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
