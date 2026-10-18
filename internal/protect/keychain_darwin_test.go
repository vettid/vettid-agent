//go:build darwin && cgo

package protect

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vettid/vettid-agent/internal/state"
)

// The macOS Keychain against the real Security framework. A test binary
// is a bare command-line binary without the keychain-access-groups
// entitlement, so these tests show the "not available" path as macOS
// answers it; the round trip needs the signed app (README, "Keys at rest
// on macOS: the Keychain", manual check).

func TestKeychainDarwinNotEntitled(t *testing.T) {
	switch keychainOS.entitlement() {
	case entitlementPresent:
		t.Skip("this test binary has the keychain-access-groups entitlement")
	case entitlementUnknown:
		t.Fatal("the entitlement of a bare test binary could not be read (expected: absent)")
	}
	// What macOS answers a binary without the entitlement, asked
	// directly: errSecMissingEntitlement for add and delete, and "not
	// found" for a lookup (which is why the protector checks its
	// entitlement before any lookup).
	name := hex.EncodeToString([]byte("vettid-agent-ci!"))
	key := make([]byte, 32)
	st := keychainOS.add(keychainProbeName, name, key)
	t.Logf("add: OSStatus %d (%s)", st, keychainOS.message(st))
	if st != errSecMissingEntitlement {
		t.Fatalf("add: OSStatus %d, want %d", st, errSecMissingEntitlement)
	}
	_, st = keychainOS.get(name)
	t.Logf("get: OSStatus %d (%s)", st, keychainOS.message(st))
	if st != errSecItemNotFound && st != errSecMissingEntitlement {
		t.Fatalf("get: OSStatus %d", st)
	}
	st = keychainOS.remove(name)
	t.Logf("remove: OSStatus %d (%s)", st, keychainOS.message(st))
	if st != errSecMissingEntitlement && st != errSecItemNotFound {
		t.Fatalf("remove: OSStatus %d", st)
	}
	if m := keychainOS.message(errSecMissingEntitlement); m == "" {
		t.Error("no message for errSecMissingEntitlement")
	}

	// The real status mapped by the protector, bypassing its own
	// entitlement check.
	k := newKeychain(bypassEntitlement{keychainOS}, keychainProbeName, nil)
	_, err := k.Wrap(make([]byte, 32))
	t.Logf("Wrap past the entitlement check: %v", err)
	checkUnavailable(t, "Wrap past the check", err)
	if !strings.Contains(err.Error(), "-34018") {
		t.Errorf("no status code: %v", err)
	}

	// The protector as pair, status and mcp get it.
	dir := t.TempDir()
	p := Platform(KeychainName, dir)
	if p == nil || p.Name() != KeychainName {
		t.Fatal("Platform(keychain)")
	}
	_, err = p.Wrap(make([]byte, 32))
	t.Logf("Wrap: %v", err)
	checkUnavailable(t, "Wrap", err)
	if !strings.Contains(err.Error(), "--passphrase") {
		t.Errorf("Wrap: no --passphrase fix: %v", err)
	}
	blob := append([]byte{keychainBlobVersion}, make([]byte, keychainBlobLen-1)...)
	_, err = p.Unwrap(blob)
	t.Logf("Unwrap: %v", err)
	checkUnavailable(t, "Unwrap", err)
	if errors.Is(err, ErrKeychainItemGone) {
		t.Error("Unwrap reported a deleted item")
	}
	if _, err := p.Unwrap(blob[1:]); !errors.Is(err, ErrKeychainBlobFormat) {
		t.Errorf("bad blob: %v", err)
	}
	err = p.Wipe()
	t.Logf("Wipe: %v", err)
	checkUnavailable(t, "Wipe", err)
	if Platform("tpm", dir) != nil || Platform(DPAPIName, dir) != nil {
		t.Error("other platform protectors in a macOS build")
	}
	// Without the entitlement WipeAll's list leaves the Keychain out
	// (keychainProtectors), so `pair --restart` over an unreadable
	// header works the first time.
	all := All(dir)
	if len(all) != 1 || all[0].Name() != PassphraseName {
		t.Errorf("All: %v", all)
	}
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.WriteFile(filepath.Join(dir, state.StateFileName), []byte("not a state file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.WipeAll(All(dir)); err != nil {
		t.Errorf("WipeAll over an unreadable header: %v", err)
	}
	if ok, err := store.Exists(); err != nil || ok {
		t.Errorf("state file left: %v %v", ok, err)
	}
}

type bypassEntitlement struct{ keychainOps }

func (bypassEntitlement) entitlement() int { return entitlementPresent }

// TestChooseProtectorDarwin: a binary without the entitlement chooses
// the passphrase, without an error, and says why and what to do.
func TestChooseProtectorDarwin(t *testing.T) {
	switch keychainOS.entitlement() {
	case entitlementPresent:
		t.Skip("this test binary has the keychain-access-groups entitlement")
	case entitlementUnknown:
		t.Fatal("the entitlement of a bare test binary could not be read (expected: absent)")
	}
	for _, fallback := range []bool{false, true} {
		c, err := ChooseProtector(ChooseOptions{AllowPassphraseFallback: fallback})
		t.Logf("fallback %v: %+v %v", fallback, c, err)
		if err != nil || c.Protector != PassphraseName || c.MachineBound || c.Notice() != NotMachineBound ||
			!strings.Contains(c.Reason, "vettid-agent.app/Contents/MacOS/vettid-agent") {
			t.Errorf("fallback %v: %+v %v", fallback, c, err)
		}
	}
}

// TestCanonicalDir: the same directory gives the same item service
// however its path is spelled (a symbolic link, "..", the letter case
// on a case-insensitive volume).
func TestCanonicalDir(t *testing.T) {
	base := t.TempDir() // under /var/folders, itself a link to /private/var
	dir := filepath.Join(base, "State")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	want, err := canonicalDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("canonical: %s", want)
	spellings := []string{link, filepath.Join(dir, "..", "State"), dir + "/"}
	if _, err := os.Stat(filepath.Join(base, "state")); err == nil {
		spellings = append(spellings, filepath.Join(base, "state")) // case-insensitive volume
	}
	for _, s := range spellings {
		got, err := canonicalDir(s)
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", s, got, err, want)
		}
	}
	if NewKeychain(link).service != NewKeychain(dir).service {
		t.Error("services differ")
	}
	if _, err := canonicalDir(""); err == nil {
		t.Error("empty path accepted")
	}
	// A directory that cannot be opened is refused, never guessed.
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", filepath.Join(base, "missing"), file} {
		if p, err := canonicalDir(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, p)
		}
		if NewKeychain(bad).dirErr == nil {
			t.Errorf("NewKeychain(%q) has no error", bad)
		}
	}
	// Wrap and Wipe refuse it (past the entitlement check).
	k := NewKeychain(filepath.Join(base, "missing"))
	k.ops = bypassEntitlement{keychainOS}
	if _, err := k.Wrap(make([]byte, 32)); err == nil || !strings.Contains(err.Error(), "could not be resolved") {
		t.Errorf("Wrap: %v", err)
	}
	if err := k.Wipe(); err == nil || !strings.Contains(err.Error(), "could not be resolved") {
		t.Errorf("Wipe: %v", err)
	}
}

// TestKeychainDarwinNoEmptyQueries: an empty account or service is
// refused by the Go layer and by the C layer, before the Keychain.
func TestKeychainDarwinNoEmptyQueries(t *testing.T) {
	if st := keychainOS.remove(""); st != -50 {
		t.Errorf("Go remove: %d", st)
	}
	if _, st := keychainOS.list(""); st != -50 {
		t.Errorf("Go list: %d", st)
	}
	if st := keychainOS.retag("", "x"); st != -50 {
		t.Errorf("Go retag: %d", st)
	}
	if st := keychainOS.retag("x", ""); st != -50 {
		t.Errorf("Go retag, empty service: %d", st)
	}
	r, l, g := cEmptyQueryStatuses()
	if r != -50 || l != -50 || g != -50 {
		t.Errorf("C guards: remove %d, list %d, retag %d", r, l, g)
	}
}
