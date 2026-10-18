package protect

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/vettid-agent/internal/state"
)

// fakeKeychain is a keychainOps over a map, for the protector's logic on
// every platform. It records deletions in order and can fail calls.
type fakeKeychain struct {
	noEntitlement bool
	entUnknown    bool
	items         map[string]keychainItem // by account
	created       map[string]float64      // by account
	clock         float64
	removed       []string // accounts, in order
	listed        []string // services listed
	retagged      []string // "account service"
	emptyQueries  int      // remove, list or retag calls with an empty argument

	addStatus    int32
	getStatus    int32
	listStatus   int32
	retagStatus  int32
	removeAny    int32            // status for every remove
	removeStatus map[string]int32 // by account
	// stored overrides what add stores (macOS storing an item otherwise
	// than asked).
	stored func(*keychainItem)
}

func newFakeKeychain() *fakeKeychain {
	return &fakeKeychain{items: map[string]keychainItem{}, created: map[string]float64{}, removeStatus: map[string]int32{}}
}

func (f *fakeKeychain) entitlement() int {
	switch {
	case f.entUnknown:
		return entitlementUnknown
	case f.noEntitlement:
		return entitlementAbsent
	}
	return entitlementPresent
}

func (f *fakeKeychain) add(service, account string, key []byte) int32 {
	if f.addStatus != 0 {
		return f.addStatus
	}
	if _, ok := f.items[account]; ok {
		return errSecDuplicateItem
	}
	it := keychainItem{data: append([]byte(nil), key...), service: service, thisDeviceOnly: true}
	if f.stored != nil {
		f.stored(&it)
	}
	f.items[account] = it
	f.clock++
	f.created[account] = f.clock
	return 0
}

func (f *fakeKeychain) get(account string) (keychainItem, int32) {
	if f.getStatus != 0 {
		return keychainItem{}, f.getStatus
	}
	it, ok := f.items[account]
	if !ok {
		return keychainItem{}, errSecItemNotFound
	}
	it.data = append([]byte(nil), it.data...)
	return it, 0
}

func (f *fakeKeychain) list(service string) ([]keychainListed, int32) {
	if service == "" {
		f.emptyQueries++
		return nil, -50
	}
	f.listed = append(f.listed, service)
	if f.listStatus != 0 {
		return nil, f.listStatus
	}
	var out []keychainListed
	for a, it := range f.items {
		if it.service == service {
			out = append(out, keychainListed{account: a, created: f.created[a]})
		}
	}
	if len(out) == 0 {
		return nil, errSecItemNotFound
	}
	return out, 0
}

func (f *fakeKeychain) retag(account, service string) int32 {
	if account == "" || service == "" {
		f.emptyQueries++
		return -50
	}
	f.retagged = append(f.retagged, account+" "+service)
	if f.retagStatus != 0 {
		return f.retagStatus
	}
	it, ok := f.items[account]
	if !ok {
		return errSecItemNotFound
	}
	it.service = service
	f.items[account] = it
	return 0
}

func (f *fakeKeychain) remove(account string) int32 {
	if account == "" {
		f.emptyQueries++
		return -50
	}
	f.removed = append(f.removed, account)
	if f.removeAny != 0 {
		return f.removeAny
	}
	if st := f.removeStatus[account]; st != 0 {
		return st
	}
	if _, ok := f.items[account]; !ok {
		return errSecItemNotFound
	}
	delete(f.items, account)
	return 0
}

func (f *fakeKeychain) message(st int32) string { return "fake message" }

func testDataKey() []byte { return bytes.Repeat([]byte{0x42}, state.DataKeyLen) }

func TestKeychainRoundTrip(t *testing.T) {
	f := newFakeKeychain()
	svc := keychainDirService("/Users/test/state")
	k := newKeychain(f, svc, nil)
	if k.Name() != KeychainName || !protectorNameOK(k.Name()) {
		t.Fatalf("name %q", k.Name())
	}
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != keychainBlobLen || keychainBlobLen != 89 || blob[0] != 1 {
		t.Fatalf("blob length %d, version %d", len(blob), blob[0])
	}
	if len(f.items) != 1 {
		t.Fatalf("%d items", len(f.items))
	}
	for a, it := range f.items {
		if it.service != svc || a != hexOf(blob[1:17]) || len(it.data) != 32 {
			t.Fatalf("item %q %q", it.service, a)
		}
		if bytes.Contains(blob, it.data) {
			t.Fatal("the blob holds the KEK")
		}
	}
	if bytes.Contains(blob, testDataKey()) {
		t.Fatal("the blob holds the data key in the clear")
	}
	// A fresh instance (another process) opens it, by the blob alone,
	// even for another state directory path (a moved directory).
	got, err := newKeychain(f, keychainDirService("/elsewhere"), nil).Unwrap(blob)
	if err != nil || !bytes.Equal(got, testDataKey()) {
		t.Fatalf("Unwrap: %v", err)
	}
	// Two Wraps make two items with different names.
	blob2, err := k.Wrap(testDataKey())
	if err != nil || bytes.Equal(blob[1:17], blob2[1:17]) || len(f.items) != 2 {
		t.Fatalf("second Wrap: %v, %d items", err, len(f.items))
	}
}

func protectorNameOK(n string) bool {
	return n != "" && len(n) <= 32 && n[0] >= 'a' && n[0] <= 'z'
}

func hexOf(b []byte) string {
	const h = "0123456789abcdef"
	var s strings.Builder
	for _, c := range b {
		s.WriteByte(h[c>>4])
		s.WriteByte(h[c&15])
	}
	return s.String()
}

// TestKeychainBlobStrict: anything but exactly version 1 and 89 bytes
// is refused before the Keychain is asked.
func TestKeychainBlobStrict(t *testing.T) {
	f := newFakeKeychain()
	k := newKeychain(f, keychainDirService("/d"), nil)
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	f.getStatus = -1 // any Keychain lookup now fails differently
	bad := map[string][]byte{
		"empty":     nil,
		"version 0": append([]byte{0}, blob[1:]...),
		"version 2": append([]byte{2}, blob[1:]...),
		"short":     blob[:len(blob)-1],
		"long":      append(append([]byte(nil), blob...), 0),
		"one byte":  {1},
	}
	for name, b := range bad {
		if _, err := k.Unwrap(b); !errors.Is(err, ErrKeychainBlobFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Also without the entitlement: the format is checked first.
	f.noEntitlement = true
	if _, err := k.Unwrap(bad["short"]); !errors.Is(err, ErrKeychainBlobFormat) {
		t.Errorf("no entitlement, bad blob: %v", err)
	}
}

// TestKeychainAltered: a changed name, nonce or sealed key is refused
// definitely, never returned as another key.
func TestKeychainAltered(t *testing.T) {
	f := newFakeKeychain()
	k := newKeychain(f, keychainDirService("/d"), nil)
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	other, err := k.Wrap(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for i := 17; i < len(blob); i++ {
		b := append([]byte(nil), blob...)
		b[i] ^= 1
		if _, err := k.Unwrap(b); !errors.Is(err, ErrKeychainRefused) {
			t.Fatalf("byte %d: %v", i, err)
		}
	}
	// The name of another item of this protector: the AEAD refuses it.
	swapped := append(append([]byte{1}, other[1:17]...), blob[17:]...)
	if _, err := k.Unwrap(swapped); !errors.Is(err, ErrKeychainRefused) {
		t.Fatalf("swapped item: %v", err)
	}
	// A name with no item: gone, definite, with the fix.
	gone := append([]byte(nil), blob...)
	gone[1] ^= 1
	_, err = k.Unwrap(gone)
	if !errors.Is(err, ErrKeychainItemGone) || !strings.Contains(err.Error(), "pair --restart") {
		t.Fatalf("missing item: %v", err)
	}
}

// TestKeychainAttributes: an item that is not ThisDeviceOnly, or is
// synchronizable, or not this protector's, is refused, at Wrap (read
// back, and deleted) and at Unwrap.
func TestKeychainAttributes(t *testing.T) {
	cases := map[string]func(*keychainItem){
		"not this device only": func(it *keychainItem) { it.thisDeviceOnly = false },
		"synchronizable":       func(it *keychainItem) { it.synchronizable = true },
		"other service":        func(it *keychainItem) { it.service = "other" },
		"other data":           func(it *keychainItem) { it.data = bytes.Repeat([]byte{9}, 32) },
	}
	for name, change := range cases {
		f := newFakeKeychain()
		f.stored = change
		k := newKeychain(f, keychainDirService("/d"), nil)
		if _, err := k.Wrap(testDataKey()); err == nil || !strings.Contains(err.Error(), "did not store the key as asked") {
			t.Errorf("Wrap, %s: %v", name, err)
		}
		if len(f.items) != 0 {
			t.Errorf("Wrap, %s: item left", name)
		}
	}
	for name, change := range cases {
		if name == "other data" {
			continue // covered by TestKeychainAltered
		}
		f := newFakeKeychain()
		k := newKeychain(f, keychainDirService("/d"), nil)
		blob, err := k.Wrap(testDataKey())
		if err != nil {
			t.Fatal(err)
		}
		for a, it := range f.items {
			change(&it)
			f.items[a] = it
		}
		if _, err := k.Unwrap(blob); !errors.Is(err, ErrKeychainRefused) {
			t.Errorf("Unwrap, %s: %v", name, err)
		}
	}
}

// TestKeychainUnavailable: without the entitlement nothing asks the
// Keychain, and every call says why and what to do.
func TestKeychainUnavailable(t *testing.T) {
	f := newFakeKeychain()
	k := newKeychain(f, keychainDirService("/d"), nil)
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	f.noEntitlement = true
	f.getStatus = errSecItemNotFound // what a binary without it is told
	_, err = k.Wrap(testDataKey())
	checkUnavailable(t, "Wrap", err)
	if !strings.Contains(err.Error(), "--passphrase") {
		t.Errorf("Wrap error has no --passphrase fix: %v", err)
	}
	_, err = k.Unwrap(blob)
	checkUnavailable(t, "Unwrap", err)
	if errors.Is(err, ErrKeychainItemGone) {
		t.Error("Unwrap without the entitlement reports a deleted item")
	}
	checkUnavailable(t, "Wipe", k.Wipe())
	if len(f.items) != 1 || len(f.removed) != 0 {
		t.Error("the Keychain was asked")
	}
	// errSecMissingEntitlement from the Keychain itself maps the same.
	f.noEntitlement, f.addStatus = false, errSecMissingEntitlement
	_, err = k.Wrap(testDataKey())
	checkUnavailable(t, "Wrap, -34018", err)
	if !strings.Contains(err.Error(), "-34018") {
		t.Errorf("no status code: %v", err)
	}
}

func checkUnavailable(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrKeychainUnavailable) || !strings.Contains(err.Error(), "signed vettid-agent app") {
		t.Errorf("%s: %v", what, err)
	}
}

// TestKeychainStatusKinds: locked and other answers are told apart from
// a definite one, and carry the status code.
func TestKeychainStatusKinds(t *testing.T) {
	f := newFakeKeychain()
	k := newKeychain(f, keychainDirService("/d"), nil)
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range []int32{errSecInteractionNotAllowed, errSecNotAvailable, errSecAuthFailed, errSecNoSuchKeychain} {
		f.getStatus = st
		_, err := k.Unwrap(blob)
		if !errors.Is(err, ErrKeychainLocked) || errors.Is(err, ErrKeychainItemGone) || errors.Is(err, ErrKeychainRefused) || !strings.Contains(err.Error(), "unlocked") {
			t.Errorf("status %d: %v", st, err)
		}
	}
	f.getStatus = -50
	_, err = k.Unwrap(blob)
	if err == nil || errors.Is(err, ErrKeychainItemGone) || errors.Is(err, ErrKeychainRefused) || !strings.Contains(err.Error(), "OSStatus -50: fake message") {
		t.Errorf("other status: %v", err)
	}
	f.getStatus = 0
	f.addStatus = errSecInteractionNotAllowed
	if _, err := k.Wrap(testDataKey()); !errors.Is(err, ErrKeychainLocked) {
		t.Errorf("Wrap, locked: %v", err)
	}
}

// TestKeychainWipe: Wipe deletes the directory's items from the header
// alone, is idempotent, and makes the blob unopenable.
func TestKeychainWipe(t *testing.T) {
	f := newFakeKeychain()
	svc := keychainDirService("/d")
	k := newKeychain(f, svc, nil)
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	other := newKeychain(f, keychainDirService("/other"), nil)
	if _, err := other.Wrap(testDataKey()); err != nil {
		t.Fatal(err)
	}
	// A fresh instance (only the header was read) finds it.
	fresh := newKeychain(f, svc, nil)
	if err := fresh.Wipe(); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Unwrap(blob); !errors.Is(err, ErrKeychainItemGone) {
		t.Fatalf("after Wipe: %v", err)
	}
	if len(f.items) != 1 {
		t.Fatal("another state directory's item was deleted")
	}
	// Idempotent: gone is nil, also for the instance that wrapped it.
	if err := fresh.Wipe(); err != nil {
		t.Fatal(err)
	}
	if err := k.Wipe(); err != nil {
		t.Fatal(err)
	}
	// It can wrap again after Wipe.
	if _, err := k.Wrap(testDataKey()); err != nil {
		t.Fatal(err)
	}
}

// TestKeychainWipeMoved: a state directory moved after pairing, opened
// at its new path, is wiped by the item name the instance remembers;
// that deletion comes last.
func TestKeychainWipeMoved(t *testing.T) {
	f := newFakeKeychain()
	blob, err := newKeychain(f, keychainDirService("/old"), nil).Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	k := newKeychain(f, keychainDirService("/new"), nil)
	if _, err := k.Unwrap(blob); err != nil {
		t.Fatal(err)
	}
	if err := k.Wipe(); err != nil {
		t.Fatal(err)
	}
	if len(f.items) != 0 {
		t.Fatal("the moved directory's item remains")
	}
	// Unwrap re-tagged it for /new; one deletion, by name.
	name := hexOf(blob[1:17])
	if len(f.removed) != 1 || f.removed[0] != name {
		t.Fatalf("deletions %v", f.removed)
	}
}

// TestKeychainWipeAllOrNothing: a failed deletion returns an error and
// leaves the key opening what it wrapped.
func TestKeychainWipeAllOrNothing(t *testing.T) {
	f := newFakeKeychain()
	svc := keychainDirService("/d")
	k := newKeychain(f, svc, nil)
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	f.listStatus = errSecInteractionNotAllowed
	if err := k.Wipe(); !errors.Is(err, ErrKeychainLocked) {
		t.Fatalf("Wipe: %v", err)
	}
	if _, err := k.Unwrap(blob); err != nil {
		t.Fatalf("after a failed Wipe: %v", err)
	}
	// Moved directory: the last step (the remembered item) fails.
	f.listStatus = 0
	k2 := newKeychain(f, keychainDirService("/moved"), nil)
	if _, err := k2.Unwrap(blob); err != nil {
		t.Fatal(err)
	}
	f.removeStatus[hexOf(blob[1:17])] = -61
	if err := k2.Wipe(); err == nil {
		t.Fatal("Wipe succeeded")
	}
	if _, err := k2.Unwrap(blob); err != nil {
		t.Fatalf("after a failed Wipe: %v", err)
	}
	delete(f.removeStatus, hexOf(blob[1:17]))
	if err := k2.Wipe(); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// No state directory: Wipe cannot find its items and Wrap makes
	// none, and both say so.
	k3 := newKeychain(f, "", errors.New("no state directory"))
	if err := k3.Wipe(); err == nil {
		t.Fatal("Wipe without a state directory succeeded")
	}
	n := len(f.items)
	if _, err := k3.Wrap(testDataKey()); err == nil || len(f.items) != n {
		t.Fatalf("Wrap without a state directory: %v", err)
	}
}

// TestKeychainDirTag: the service names the directory by a hash, not
// its path, and differs per directory.
func TestKeychainDirTag(t *testing.T) {
	a, b := keychainDirService("/Users/a/state"), keychainDirService("/Users/b/state")
	if a == b || !strings.HasPrefix(a, "vettid-agent/") || len(a) != len("vettid-agent/")+32 || strings.Contains(a, "Users") {
		t.Fatalf("%q %q", a, b)
	}
	if a != keychainDirService("/Users/a/state") {
		t.Fatal("not deterministic")
	}
}

// TestChooseKeychain: the selection rules (chooseKeychain).
func TestChooseKeychain(t *testing.T) {
	// No entitlement: the passphrase, no error, with the reason and fix,
	// also when --passphrase is given.
	f := newFakeKeychain()
	f.noEntitlement = true
	for _, fallback := range []bool{false, true} {
		c, err := chooseKeychain(f, ChooseOptions{AllowPassphraseFallback: fallback})
		if err != nil || c.Protector != PassphraseName || c.MachineBound || c.Notice() == "" ||
			!strings.Contains(c.Reason, "signed vettid-agent app") || !strings.HasSuffix(c.Reason, "; using a passphrase") {
			t.Errorf("no entitlement (fallback %v): %+v %v", fallback, c, err)
		}
	}
	// Works: the Keychain, and the probe item is deleted.
	f = newFakeKeychain()
	c, err := chooseKeychain(f, ChooseOptions{})
	if err != nil || c.Protector != KeychainName || !c.MachineBound || c.Notice() != "" {
		t.Fatalf("works: %+v %v", c, err)
	}
	if len(f.items) != 0 || len(f.listed) != 1 || !strings.HasPrefix(f.listed[0], keychainProbeName) {
		t.Fatalf("probe left %d items, listed %v", len(f.items), f.listed)
	}
	// Present but failing: an error with cause and fix, unless the
	// operator asked for a passphrase.
	for name, setup := range map[string]func(*fakeKeychain){
		"locked":                 func(f *fakeKeychain) { f.addStatus = errSecInteractionNotAllowed },
		"stored as sync":         func(f *fakeKeychain) { f.stored = func(it *keychainItem) { it.synchronizable = true } },
		"not deleted":            func(f *fakeKeychain) { f.removeAny = -61 },
		"entitlement unreadable": func(f *fakeKeychain) { f.entUnknown = true },
	} {
		f := newFakeKeychain()
		setup(f)
		_, err := chooseKeychain(f, ChooseOptions{})
		if err == nil || !strings.Contains(err.Error(), "or choose a passphrase instead") {
			t.Errorf("%s: %v", name, err)
		}
		c, err := chooseKeychain(f, ChooseOptions{AllowPassphraseFallback: true})
		if err != nil || c.Protector != PassphraseName || c.MachineBound || !strings.Contains(c.Reason, "Keychain") {
			t.Errorf("%s, fallback: %+v %v", name, c, err)
		}
	}
}

// TestKeychainRetag: an item opened from another state directory than
// the one it is tagged with follows the file, so that a new pairing at
// the old path and its Wipe leave it alone. Rename A to B, open B, pair
// again in a new A, wipe A from the header: B still opens.
func TestKeychainRetag(t *testing.T) {
	f := newFakeKeychain()
	svcA, svcB := keychainDirService("/A"), keychainDirService("/B")
	blobB, err := newKeychain(f, svcA, nil).Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	// A renamed to B, opened there (status, mcp).
	if _, err := newKeychain(f, svcB, nil).Unwrap(blobB); err != nil {
		t.Fatal(err)
	}
	if it := f.items[hexOf(blobB[1:17])]; it.service != svcB {
		t.Fatalf("not re-tagged: %q", it.service)
	}
	// A new pairing in a new A, then a Wipe of A from its header.
	if _, err := newKeychain(f, svcA, nil).Wrap(testDataKey()); err != nil {
		t.Fatal(err)
	}
	if err := newKeychain(f, svcA, nil).Wipe(); err != nil {
		t.Fatal(err)
	}
	if _, err := newKeychain(f, svcB, nil).Unwrap(blobB); err != nil {
		t.Fatalf("B no longer opens after wiping A: %v", err)
	}
	if len(f.items) != 1 {
		t.Fatalf("%d items", len(f.items))
	}
	// Opened where it is tagged: no re-tag.
	n := len(f.retagged)
	if _, err := newKeychain(f, svcB, nil).Unwrap(blobB); err != nil || len(f.retagged) != n {
		t.Fatalf("re-tagged in place: %v %v", err, f.retagged)
	}
	// A failed re-tag does not fail Unwrap; the tag stays.
	f.retagStatus = errSecInteractionNotAllowed
	if _, err := newKeychain(f, keychainDirService("/C"), nil).Unwrap(blobB); err != nil {
		t.Fatalf("Unwrap with a failed re-tag: %v", err)
	}
	if it := f.items[hexOf(blobB[1:17])]; it.service != svcB {
		t.Fatalf("service changed: %q", it.service)
	}
	// An unresolved directory opens without re-tagging.
	f.retagStatus = 0
	n = len(f.retagged)
	if _, err := newKeychain(f, "", errors.New("no state directory")).Unwrap(blobB); err != nil || len(f.retagged) != n {
		t.Fatalf("unresolved directory: %v %v", err, f.retagged)
	}
}

// TestKeychainWipeInUseLast: the key in use is deleted last, and every
// failure comes before it, so an error means it is intact.
func TestKeychainWipeInUseLast(t *testing.T) {
	// Header only: three items of the directory; the newest is the key
	// in use and is deleted last.
	f := newFakeKeychain()
	svc := keychainDirService("/d")
	var names []string
	for i := 0; i < 3; i++ {
		b, err := newKeychain(f, svc, nil).Wrap(testDataKey())
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hexOf(b[1:17]))
	}
	if err := newKeychain(f, svc, nil).Wipe(); err != nil || len(f.items) != 0 {
		t.Fatalf("Wipe: %v, %d left", err, len(f.items))
	}
	if len(f.removed) != 3 || f.removed[2] != names[2] {
		t.Fatalf("deletions %v, newest %s", f.removed, names[2])
	}

	// Loaded: the key this instance opened is last, even if it is not
	// the newest; a failure on another item leaves it intact.
	f = newFakeKeychain()
	inUse, err := newKeychain(f, svc, nil).Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := newKeychain(f, svc, nil).Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	k := newKeychain(f, svc, nil)
	if _, err := k.Unwrap(inUse); err != nil {
		t.Fatal(err)
	}
	f.removeStatus[hexOf(orphan[1:17])] = errSecInteractionNotAllowed
	if err := k.Wipe(); err == nil {
		t.Fatal("Wipe succeeded")
	}
	if _, err := k.Unwrap(inUse); err != nil {
		t.Fatalf("the key in use was deleted by a failed Wipe: %v", err)
	}
	delete(f.removeStatus, hexOf(orphan[1:17]))
	f.removed = nil
	if err := k.Wipe(); err != nil {
		t.Fatal(err)
	}
	if len(f.removed) != 2 || f.removed[1] != hexOf(inUse[1:17]) {
		t.Fatalf("deletions %v", f.removed)
	}
	if _, err := k.Unwrap(inUse); !errors.Is(err, ErrKeychainItemGone) {
		t.Fatalf("after Wipe: %v", err)
	}
}

// TestKeychainNoEmptyQueries: no call ever reaches the Keychain with an
// empty service or account (which would widen it to every item).
func TestKeychainNoEmptyQueries(t *testing.T) {
	f := newFakeKeychain()
	k := newKeychain(f, keychainDirService("/d"), nil)
	if err := k.Wipe(); err != nil { // nothing listed, nothing opened
		t.Fatal(err)
	}
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newKeychain(f, keychainDirService("/e"), nil).Unwrap(blob); err != nil {
		t.Fatal(err)
	}
	if err := k.Wipe(); err != nil {
		t.Fatal(err)
	}
	if _, err := chooseKeychain(f, ChooseOptions{}); err != nil {
		t.Fatal(err)
	}
	if f.emptyQueries != 0 {
		t.Fatalf("%d calls with an empty service or account", f.emptyQueries)
	}
}

// TestKeychainEntitlementUnknown: an entitlement that cannot be read is
// "present but failing": every call refuses with the cause and the fix,
// and the selection needs --passphrase.
func TestKeychainEntitlementUnknown(t *testing.T) {
	f := newFakeKeychain()
	k := newKeychain(f, keychainDirService("/d"), nil)
	blob, err := k.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	f.entUnknown = true
	_, werr := k.Wrap(testDataKey())
	_, uerr := k.Unwrap(blob)
	for what, err := range map[string]error{"Wrap": werr, "Unwrap": uerr, "Wipe": k.Wipe()} {
		if !errors.Is(err, ErrKeychainEntitlementUnknown) || errors.Is(err, ErrKeychainUnavailable) || !strings.Contains(err.Error(), "--passphrase") {
			t.Errorf("%s: %v", what, err)
		}
	}
	if len(f.items) != 1 {
		t.Error("an item was deleted")
	}
	if _, err := chooseKeychain(f, ChooseOptions{}); !errors.Is(err, ErrKeychainEntitlementUnknown) {
		t.Errorf("choose: %v", err)
	}
	if c, err := chooseKeychain(f, ChooseOptions{AllowPassphraseFallback: true}); err != nil || c.Protector != PassphraseName {
		t.Errorf("choose with --passphrase: %+v %v", c, err)
	}
}

// TestKeychainProbeOwnService: each probe uses a service of its own and
// never deletes another probe's item (concurrent `pair` runs).
func TestKeychainProbeOwnService(t *testing.T) {
	f := newFakeKeychain()
	// Another run's probe, still in progress.
	other := newKeychain(f, keychainProbeName+"0123456789abcdef0123456789abcdef", nil)
	blob, err := other.Wrap(testDataKey())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := tryKeychain(f); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.listed) != 2 || f.listed[0] == f.listed[1] || !strings.HasPrefix(f.listed[0], keychainProbeName) {
		t.Fatalf("probe services %v", f.listed)
	}
	if _, err := other.Unwrap(blob); err != nil {
		t.Fatalf("another probe's item was deleted: %v", err)
	}
}

// TestKeychainProtectorsForWipeAll: a build that certainly lacks the
// entitlement leaves the Keychain protector out of WipeAll's list (its
// Wipe could only fail, after WipeAll had removed the files anyway); a
// build that has it, or cannot tell, keeps it.
func TestKeychainProtectorsForWipeAll(t *testing.T) {
	f := newFakeKeychain()
	k := newKeychain(f, keychainDirService("/d"), nil)
	names := func() []string {
		var out []string
		for _, p := range keychainProtectors(f, k) {
			out = append(out, p.Name())
		}
		return out
	}
	if got := strings.Join(names(), ","); got != "keychain,passphrase" {
		t.Errorf("entitled: %s", got)
	}
	f.entUnknown = true
	if got := strings.Join(names(), ","); got != "keychain,passphrase" {
		t.Errorf("unknown: %s", got)
	}
	f.entUnknown, f.noEntitlement = false, true
	if got := strings.Join(names(), ","); got != "passphrase" {
		t.Errorf("absent: %s", got)
	}
}
