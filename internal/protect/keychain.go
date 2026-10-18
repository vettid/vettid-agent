package protect

// The macOS Keychain protector (AGENT-PLAN §2 AG3, §4.2, §6 A1.5). The
// logic is here, without a build tag, so that it is tested on every
// platform against a fake Keychain; the Keychain calls (cgo) are in
// keychain_darwin.go.
//
// Construction:
//
//   - Wrap makes a random 256-bit key-encryption key (KEK) and stores it
//     as a generic password item in the data protection keychain
//     (kSecUseDataProtectionKeychain) with
//     kSecAttrAccessibleWhenUnlockedThisDeviceOnly and
//     kSecAttrSynchronizable false: macOS keeps such an item on this Mac
//     only (it is not synced with iCloud Keychain and not restored from a
//     backup to another Mac), and gives it only to this user while the
//     Mac is unlocked. The data key is sealed under the KEK with
//     XChaCha20-Poly1305; the sealed data key and the item's random name
//     are the wrapped blob. The state file alone opens nowhere; the item
//     alone holds no data key.
//   - Only the data protection keychain is used, never the file-based
//     login keychain: the file-based keychain silently drops
//     ThisDeviceOnly, and its access control list stops a rebuilt binary
//     on a dialog. The data protection keychain needs the
//     keychain-access-groups entitlement, which macOS grants only to a
//     signed app whose provisioning profile allows it (A5); a binary
//     without it (a source build, a bare command-line binary) gets
//     errSecMissingEntitlement, and its lookups find nothing. So the
//     protector first checks its own entitlement, and without it reports
//     ErrKeychainUnavailable (with the fix) instead of asking the
//     Keychain; a lookup that finds nothing is then never mistaken for a
//     deleted item.
//   - Wrap reads the item back and checks the KEK and the attributes
//     (ThisDeviceOnly, not synchronizable) before it returns a blob;
//     Unwrap checks the same attributes before it uses the KEK. An item
//     macOS stored otherwise is refused, so the protector is not chosen
//     (ChooseProtector probes it) rather than silently weaker.
//
// Item attributes: kSecClass generic password; kSecAttrService
// "vettid-agent/" followed by keychainDirTag of the state directory;
// kSecAttrAccount the item's random 16-byte name in lower-case hex;
// kSecAttrLabel "vettid-agent data key"; kSecValueData the 32-byte KEK.
//
// The wrapped blob:
//
//	blob  = version (1 byte, 0x01) || name (16 bytes) || nonce (24 bytes) || sealed
//	sealed = XChaCha20-Poly1305(KEK, nonce, data key (32 bytes),
//	                            ad = keychainADLabel || version || name)
//
// exactly 89 bytes; anything else is refused before the Keychain is
// asked.
//
// Errors from Unwrap are of three kinds. Definite: ErrKeychainItemGone
// (no item of that name for this user on this Mac: it was deleted, the
// state file comes from another Mac or user or from a backup restored to
// a new Mac, or the item was made by a build signed by someone else) and
// ErrKeychainRefused (the item does not have this protector's attributes,
// or the sealed key does not open under it: an altered file). Environmental:
// ErrKeychainLocked (the Keychain is locked or not reachable in this
// session, for example over SSH with no one logged in at the Mac) and
// ErrKeychainUnavailable (this build cannot use the data protection
// keychain). Anything else keeps the Keychain's status code and message.
//
// Unwrap re-tags an item it opens whose service names another state
// directory (the directory was moved or renamed after pairing, or the
// file was copied) with the current directory's service
// (SecItemUpdate), so that a new pairing made at the old path, and a
// later Wipe there, cannot reach it. A failed re-tag does not fail
// Unwrap; it is logged at debug level.
//
// Wipe deletes the items, one by one by name: every item listed under
// this state directory's service (found without the blob, so a Wipe from
// the header alone works) and every item this protector instance wrapped
// or unwrapped. The key in use is deleted last, as Wipe's last action:
// it is the newest item this instance wrapped or unwrapped or, for an
// instance that has opened nothing (a Wipe from the header alone), the
// newest listed item (kSecAttrCreationDate). Every step that can fail
// (the entitlement, the directory, the listing, the other deletions)
// comes before it, and nothing that can fail comes after it, so a Wipe
// that returns an error has not deleted the key in use. An item already
// gone counts as deleted, so Wipe is idempotent. Without the entitlement
// Wipe cannot look, and says so.
//
// Not covered: an item made for a state directory that was later moved,
// and wiped at the new path without its file ever having been opened
// there (its header only), stays in the Keychain; it opens nothing
// without an old copy of the state file. For a Wipe from the header
// alone, "the key in use is the newest item" can be wrong only when such
// a never-opened moved item is newer than the directory's own; then a
// failure of the last deletion can follow the deletion of the key in
// use. An item is also left when the process stops between Wrap and the
// state file being written; the next Wipe of the same state directory
// deletes it.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-agent/internal/state"
)

const (
	// KeychainName is the Keychain protector's name in the state file
	// header.
	KeychainName = "keychain"

	keychainBlobVersion = 1
	keychainNameLen     = 16
	keychainKEKLen      = chacha20poly1305.KeySize
	keychainBlobLen     = 1 + keychainNameLen + chacha20poly1305.NonceSizeX + state.DataKeyLen + chacha20poly1305.Overhead

	keychainADLabel   = "vettid-agent/protect/keychain/v1\x00"
	keychainDirLabel  = "vettid-agent/protect/keychain/v1 dir\x00"
	keychainService   = "vettid-agent/"
	keychainLabel     = "vettid-agent data key"
	keychainProbeName = keychainService + "probe/"
)

// What keychainOps.entitlement reports.
const (
	entitlementAbsent  = 0
	entitlementPresent = 1
	// entitlementUnknown: the entitlement could not be read (the
	// Security framework failed, or the value has an unexpected form).
	entitlementUnknown = -1
)

// Keychain status codes (Security/SecBase.h) the protector tells apart.
const (
	errSecSuccess               = 0
	errSecItemNotFound          = -25300
	errSecDuplicateItem         = -25299
	errSecInteractionNotAllowed = -25308
	errSecNotAvailable          = -25291
	errSecAuthFailed            = -25293
	errSecNoSuchKeychain        = -25294
	errSecMissingEntitlement    = -34018
)

var (
	// ErrKeychainBlobFormat: the wrapped key is not a Keychain protector
	// blob.
	ErrKeychainBlobFormat = errors.New("the wrapped key is not in the Keychain protector's format")
	// ErrKeychainUnavailable: this build of vettid-agent cannot use the
	// data protection keychain (no keychain-access-groups entitlement).
	ErrKeychainUnavailable = errors.New("this vettid-agent build cannot use the macOS Keychain: only the signed vettid-agent app has the keychain-access-groups entitlement it needs (a source build or a bare command-line binary does not)")
	// ErrKeychainItemGone: no Keychain item holds the state file's key
	// for this user on this Mac (definite).
	ErrKeychainItemGone = errors.New("the macOS Keychain has no item for the state file's key: it was deleted, or the state file comes from another Mac or another user (or a backup restored to a new Mac), or it was paired with a vettid-agent app signed by someone else")
	// ErrKeychainRefused: the Keychain item is not this protector's, or
	// the sealed key does not open under it (definite).
	ErrKeychainRefused = errors.New("the macOS Keychain item does not open the state file's key: the file was altered, or the item was not made by this connector")
	// ErrKeychainLocked: the Keychain is locked or not reachable in this
	// session (environmental).
	ErrKeychainLocked = errors.New("the macOS Keychain is locked or not reachable in this session")
	// ErrKeychainEntitlementUnknown: vettid-agent could not read its own
	// entitlements, so it cannot tell whether it may use the Keychain
	// (present but failing, not absent).
	ErrKeychainEntitlementUnknown = errors.New("vettid-agent could not read its own entitlements, so it cannot tell whether it may use the macOS Keychain")
)

// Fixes added to the errors above.
const (
	keychainUnavailableFix = "use the signed vettid-agent app (vettid-agent.app/Contents/MacOS/vettid-agent), or pair with --passphrase (not bound to this computer)"
	keychainLockedFix      = "run the connector as the logged-in user while the Mac is unlocked (not over SSH or from a launch daemon with no one logged in at the Mac)"
	keychainGoneFix        = "if the item was deleted or the file was copied from elsewhere, pair again (`vettid-agent pair --restart`)"
	keychainEntitlementFix = "reinstall the signed vettid-agent app, or pair with --passphrase (not bound to this computer)"
)

// keychainListed is an item a listing returns.
type keychainListed struct {
	account string
	created float64 // kSecAttrCreationDate, seconds since 2001-01-01 UTC
}

// keychainItem is what a Keychain lookup returns.
type keychainItem struct {
	data           []byte
	service        string
	thisDeviceOnly bool // kSecAttrAccessible is WhenUnlockedThisDeviceOnly
	synchronizable bool
}

// keychainOps are the Keychain calls; keychain_darwin.go has the real
// ones, tests a fake. Status codes are OSStatus values.
type keychainOps interface {
	// entitlement reports whether this process has the
	// keychain-access-groups entitlement: entitlementPresent,
	// entitlementAbsent or entitlementUnknown.
	entitlement() int
	// add stores key as a generic password in the data protection
	// keychain, ThisDeviceOnly and not synchronizable.
	add(service, account string, key []byte) int32
	// get looks an item up by its account, in the data protection
	// keychain, without any user interface.
	get(account string) (keychainItem, int32)
	// list returns the items with this service (never "").
	list(service string) ([]keychainListed, int32)
	// retag sets the service of the item with this account (neither
	// may be "").
	retag(account, service string) int32
	// remove deletes the item with this account (never "": an empty
	// account must not become a query that matches every item).
	remove(account string) int32
	// message is the Keychain's text for a status code, or "".
	message(status int32) string
}

// Keychain is the macOS Keychain protector for one state directory.
type Keychain struct {
	ops     keychainOps
	service string // keychainService + the state directory's tag
	dirErr  error  // the state directory could not be resolved
	names   []string
}

var _ state.Protector = (*Keychain)(nil)

func newKeychain(ops keychainOps, service string, dirErr error) *Keychain {
	return &Keychain{ops: ops, service: service, dirErr: dirErr}
}

// keychainDirService is the item service for a state directory given by
// its canonical path.
func keychainDirService(canonical string) string {
	return keychainService + keychainDirTag(canonical)
}

// keychainDirTag is the first 16 bytes of SHA-256(keychainDirLabel ||
// path) in lower-case hex: it names the state directory without putting
// its path in the Keychain.
func keychainDirTag(canonical string) string {
	sum := sha256.Sum256([]byte(keychainDirLabel + canonical))
	return hex.EncodeToString(sum[:16])
}

// usable returns nil if this process may use the data protection
// keychain, else why not; context ends the "not available" message.
func usable(ops keychainOps, context string) error {
	switch ops.entitlement() {
	case entitlementPresent:
		return nil
	case entitlementAbsent:
		return fmt.Errorf("%w%s", ErrKeychainUnavailable, context)
	default:
		return fmt.Errorf("%w; %s", ErrKeychainEntitlementUnknown, keychainEntitlementFix)
	}
}

// Name returns "keychain".
func (*Keychain) Name() string { return KeychainName }

func (k *Keychain) remember(name string) {
	for _, n := range k.names {
		if n == name {
			return
		}
	}
	k.names = append(k.names, name)
}

// Wrap stores a new KEK in the Keychain and seals dataKey under it.
func (k *Keychain) Wrap(dataKey []byte) ([]byte, error) {
	if len(dataKey) != state.DataKeyLen {
		return nil, errors.New("Keychain protector: data key length")
	}
	if err := usable(k.ops, "; "+keychainUnavailableFix); err != nil {
		return nil, err
	}
	if k.dirErr != nil {
		// An item made now could not be found by a Wipe from the header.
		return nil, fmt.Errorf("Keychain protector: the state directory could not be resolved: %w", k.dirErr)
	}
	kek := make([]byte, keychainKEKLen)
	defer clear(kek)
	id := make([]byte, keychainNameLen)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	for _, b := range [][]byte{kek, id, nonce} {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
	}
	name := hex.EncodeToString(id)
	if st := k.ops.add(k.service, name, kek); st != errSecSuccess {
		return nil, k.statusError("store a new key", st, false)
	}
	// Read the item back: the KEK and the attributes must be what was
	// asked for, or the item is deleted and nothing is returned.
	item, st := k.ops.get(name)
	if st != errSecSuccess {
		k.ops.remove(name)
		return nil, k.statusError("read back the new key", st, false)
	}
	defer clear(item.data)
	if subtle.ConstantTimeCompare(item.data, kek) != 1 || !item.thisDeviceOnly || item.synchronizable || item.service != k.service {
		k.ops.remove(name)
		return nil, errors.New("Keychain protector: macOS did not store the key as asked (this Mac only, not synchronized), so it is not used")
	}
	blob := make([]byte, 0, keychainBlobLen)
	blob = append(blob, keychainBlobVersion)
	blob = append(blob, id...)
	blob = append(blob, nonce...)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		k.ops.remove(name)
		return nil, err
	}
	blob = aead.Seal(blob, nonce, dataKey, keychainAD(blob[:1+keychainNameLen]))
	k.remember(name)
	return blob, nil
}

// Unwrap checks the blob's format, reads the KEK from the Keychain and
// opens the data key.
func (k *Keychain) Unwrap(blob []byte) ([]byte, error) {
	id, nonce, sealed, err := decodeKeychainBlob(blob)
	if err != nil {
		return nil, err
	}
	if err := usable(k.ops, ", and the state file's key is in the Keychain; use the signed vettid-agent app"); err != nil {
		return nil, err
	}
	name := hex.EncodeToString(id)
	item, st := k.ops.get(name)
	if st != errSecSuccess {
		return nil, k.statusError("open the key", st, true)
	}
	defer clear(item.data)
	if !item.thisDeviceOnly || item.synchronizable || !strings.HasPrefix(item.service, keychainService) || len(item.data) != keychainKEKLen {
		return nil, ErrKeychainRefused
	}
	aead, err := chacha20poly1305.NewX(item.data)
	if err != nil {
		return nil, ErrKeychainRefused
	}
	key, err := aead.Open(nil, nonce, sealed, keychainAD(blob[:1+keychainNameLen]))
	if err != nil {
		return nil, ErrKeychainRefused
	}
	if k.dirErr == nil && item.service != k.service {
		// Opened from another directory than the one the item is
		// tagged with: follow the file (see the top of this file).
		if st := k.ops.retag(name, k.service); st != errSecSuccess {
			slog.Debug("keychain protector: could not re-tag the item for this state directory", "status", st)
		}
	}
	k.remember(name)
	return key, nil
}

// Wipe deletes this state directory's items and the items this
// instance wrapped or unwrapped, the key in use last (see the top of
// this file). Items already gone count as deleted.
func (k *Keychain) Wipe() error {
	if err := usable(k.ops, ", so it cannot check for or delete the state file's Keychain item; use the signed vettid-agent app to wipe"); err != nil {
		return err
	}
	if k.dirErr != nil {
		return fmt.Errorf("Keychain protector: the state directory could not be resolved, so its Keychain items cannot be found: %w", k.dirErr)
	}
	listed, st := k.ops.list(k.service)
	switch st {
	case errSecSuccess:
	case errSecItemNotFound:
		listed = nil
	default:
		return k.statusError("list the keys", st, false)
	}
	inUse := ""
	if n := len(k.names); n > 0 {
		inUse = k.names[n-1]
	} else {
		var newest float64
		for _, it := range listed {
			if inUse == "" || it.created > newest {
				inUse, newest = it.account, it.created
			}
		}
	}
	var others []string
	seen := map[string]bool{inUse: true, "": true}
	for _, it := range listed {
		if !seen[it.account] {
			seen[it.account] = true
			others = append(others, it.account)
		}
	}
	for _, n := range k.names {
		if !seen[n] {
			seen[n] = true
			others = append(others, n)
		}
	}
	for _, a := range others {
		if st := k.ops.remove(a); st != errSecSuccess && st != errSecItemNotFound {
			return k.statusError("delete an old key", st, false)
		}
	}
	// The last action that can fail: the key in use.
	if inUse != "" {
		if st := k.ops.remove(inUse); st != errSecSuccess && st != errSecItemNotFound {
			return k.statusError("delete the key", st, false)
		}
	}
	k.names = nil
	return nil
}

// keychainAD is the associated data for the sealed data key.
func keychainAD(head []byte) []byte {
	return append([]byte(keychainADLabel), head...)
}

// decodeKeychainBlob checks a blob's length and version and splits it.
func decodeKeychainBlob(blob []byte) (id, nonce, sealed []byte, err error) {
	if len(blob) != keychainBlobLen || blob[0] != keychainBlobVersion {
		return nil, nil, nil, ErrKeychainBlobFormat
	}
	id = blob[1 : 1+keychainNameLen]
	nonce = blob[1+keychainNameLen : 1+keychainNameLen+chacha20poly1305.NonceSizeX]
	sealed = blob[1+keychainNameLen+chacha20poly1305.NonceSizeX:]
	return id, nonce, sealed, nil
}

// statusError maps a Keychain status code to an error with its fix.
// opening is true for Unwrap, where a missing item is definite.
func (k *Keychain) statusError(step string, st int32, opening bool) error {
	code := fmt.Sprintf("OSStatus %d", st)
	if m := k.ops.message(st); m != "" {
		code += ": " + m
	}
	switch st {
	case errSecMissingEntitlement:
		return fmt.Errorf("%w; %s (%s)", ErrKeychainUnavailable, keychainUnavailableFix, code)
	case errSecInteractionNotAllowed, errSecNotAvailable, errSecAuthFailed, errSecNoSuchKeychain:
		return fmt.Errorf("%w; %s (%s)", ErrKeychainLocked, keychainLockedFix, code)
	case errSecItemNotFound:
		if opening {
			return fmt.Errorf("%w; %s (%s)", ErrKeychainItemGone, keychainGoneFix, code)
		}
	}
	return fmt.Errorf("Keychain protector: %s: %s", step, code)
}

// chooseKeychain is ChooseProtector for macOS (AGENT-PLAN §2 AG3):
//
//   - this build has no keychain-access-groups entitlement (a source
//     build, a bare command-line binary): the passphrase protector, with
//     the reason and the fix, and no error. The entitlement is a property
//     of the binary, not of this Mac or its user: nothing on this Mac can
//     make this binary use the Keychain, as nothing can give a TPM to a
//     computer that has none;
//   - the Keychain works (a probe item is stored ThisDeviceOnly and not
//     synchronizable, read back, opens a probe key and is deleted): the
//     Keychain protector;
//   - the entitlement cannot be read, or the binary has it but the
//     Keychain fails (locked, no login session, macOS stored the probe
//     otherwise): an error naming
//     the cause and the fix, unless opts.AllowPassphraseFallback is set
//     (the operator asked for a passphrase), in which case the passphrase
//     protector with that cause as the reason.
func chooseKeychain(ops keychainOps, opts ChooseOptions) (Choice, error) {
	passphrase := func(reason string) Choice {
		return Choice{Protector: PassphraseName, Reason: reason + "; using a passphrase"}
	}
	if ops.entitlement() == entitlementAbsent {
		return passphrase("this vettid-agent build cannot use the macOS Keychain (only the signed vettid-agent app can: run it from vettid-agent.app/Contents/MacOS/vettid-agent to bind keys to this Mac)"), nil
	}
	err := usable(ops, "")
	if err == nil {
		err = tryKeychain(ops)
	}
	if err == nil {
		return Choice{Protector: KeychainName, Reason: "macOS Keychain, this Mac only", MachineBound: true}, nil
	}
	if opts.AllowPassphraseFallback {
		return passphrase(err.Error()), nil
	}
	return Choice{}, fmt.Errorf("%w; or choose a passphrase instead (not bound to this computer)", err)
}

// tryKeychain wraps, unwraps and wipes a random probe key under a probe
// service of its own (never a state directory's, and never another
// probe's: concurrent `pair` runs cannot delete each other's probe).
func tryKeychain(ops keychainOps) error {
	key := make([]byte, state.DataKeyLen)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	suffix := make([]byte, 16)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	p := newKeychain(ops, keychainProbeName+hex.EncodeToString(suffix), nil)
	blob, err := p.Wrap(key)
	if err != nil {
		return fmt.Errorf("the macOS Keychain does not work for this user: %w", err)
	}
	got, err := p.Unwrap(blob)
	if err != nil {
		p.Wipe()
		return fmt.Errorf("the macOS Keychain does not open what it just stored: %w", err)
	}
	defer clear(got)
	if subtle.ConstantTimeCompare(got, key) != 1 {
		p.Wipe()
		return errors.New("the macOS Keychain returned another key than it was given")
	}
	if err := p.Wipe(); err != nil {
		return fmt.Errorf("the macOS Keychain does not delete what it stored: %w", err)
	}
	return nil
}

// keychainProtectors is All for macOS: the Keychain protector unless
// this build certainly lacks the entitlement, and the passphrase
// protector. Without the entitlement the Keychain protector's Wipe could
// only fail: it cannot see or delete any item, and this build cannot
// have made one. WipeAll removes the state files whatever its protectors
// answer, so that failure would protect nothing and would only make the
// first `pair --restart` over an unreadable header fail (the second, with
// no file left, would work). An item the signed app made for this
// directory stays; it opens nothing without an old copy of the state
// file, and the signed app's next wipe of the directory deletes it.
func keychainProtectors(ops keychainOps, k *Keychain) []state.Protector {
	if ops.entitlement() == entitlementAbsent {
		return []state.Protector{&Passphrase{}}
	}
	return []state.Protector{k, &Passphrase{}}
}
