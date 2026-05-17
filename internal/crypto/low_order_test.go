package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestHasSmallOrder_BlacklistedPoints(t *testing.T) {
	for i, p := range smallOrderPoints {
		if !hasSmallOrder(p[:]) {
			t.Errorf("hasSmallOrder rejected blacklist entry %d", i)
		}
	}
}

func TestHasSmallOrder_HonestKey(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if hasSmallOrder(pub) {
		t.Errorf("honest derived pub key was flagged as small-order")
	}
}

func TestSafeX25519_RejectsBlacklist(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	for i, p := range smallOrderPoints {
		if _, err := safeX25519(priv, p[:]); err == nil {
			t.Errorf("safeX25519 accepted blacklist entry %d", i)
		}
	}
}

func TestSafeX25519_AcceptsHonest(t *testing.T) {
	aPriv := make([]byte, 32)
	bPriv := make([]byte, 32)
	if _, err := rand.Read(aPriv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(bPriv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	aPub, err := curve25519.X25519(aPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive A pub: %v", err)
	}
	bPub, err := curve25519.X25519(bPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive B pub: %v", err)
	}
	ab, err := safeX25519(aPriv, bPub)
	if err != nil {
		t.Fatalf("safeX25519 rejected honest A→B: %v", err)
	}
	ba, err := safeX25519(bPriv, aPub)
	if err != nil {
		t.Fatalf("safeX25519 rejected honest B→A: %v", err)
	}
	if !bytes.Equal(ab, ba) {
		t.Errorf("ECDH did not converge")
	}
}
