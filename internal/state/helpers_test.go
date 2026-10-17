package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// fixedProtector is a test-only protector with a fixed key and a fixed
// wrapping nonce, so that the vectors are reproducible. A fixed nonce is
// acceptable only here: real protectors draw a fresh nonce per wrap.
type fixedProtector struct {
	name  string
	key   []byte
	nonce []byte
	wiped int
}

const testProtectorName = "test-fixed"

func newFixedProtector(key []byte) *fixedProtector {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	for i := range nonce {
		nonce[i] = 0xa0 + byte(i)
	}
	return &fixedProtector{name: testProtectorName, key: key, nonce: nonce}
}

func (p *fixedProtector) Name() string { return p.name }

func (p *fixedProtector) Wrap(dataKey []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(p.key)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, p.nonce...)
	return aead.Seal(out, p.nonce, dataKey, []byte(p.name)), nil
}

func (p *fixedProtector) Unwrap(wrapped []byte) ([]byte, error) {
	if len(wrapped) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, errors.New("wrapped key too short")
	}
	aead, err := chacha20poly1305.NewX(p.key)
	if err != nil {
		return nil, err
	}
	n := chacha20poly1305.NonceSizeX
	k, err := aead.Open(nil, wrapped[:n], wrapped[n:], []byte(p.name))
	if err != nil {
		return nil, errors.New("wrapped key does not open under this key")
	}
	return k, nil
}

func (p *fixedProtector) Wipe() error { p.wiped++; return nil }

// seq returns n bytes start, start+1, ...
func seq(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func resolverFor(ps ...Protector) Resolver {
	return func(name string) Protector {
		for _, p := range ps {
			if p.Name() == name {
				return p
			}
		}
		return nil
	}
}

// openTest opens a store in a fresh state directory under t.TempDir.
func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}
