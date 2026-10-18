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
// Wipe deletes the items: every item whose service is this state
// directory's (found without the blob, so a Wipe from the header alone
// works), and then every item this protector instance wrapped or
// unwrapped (so a state directory that was moved or renamed after
// pairing is still wiped when its file was opened). An item that is
// already gone counts as deleted, so Wipe is idempotent. The deletion
// of the key opened in this process comes last, so a failed Wipe leaves
// it intact. Without the entitlement Wipe cannot look, and says so.
//
// Not covered: an item made for a state directory that was later moved,
// when the file at the new path is wiped without being opened (its
// header only), stays in the Keychain; it opens nothing without an old
// copy of the state file. An item is also left when the process stops
// between Wrap and the state file being written; the next Wipe of the
// same state directory deletes it.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
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
	keychainProbeName = keychainService + "probe"

	// maxKeychainDeletes bounds Wipe's repeated deletion of a state
	// directory's items.
	maxKeychainDeletes = 64
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
)

// Fixes added to the errors above.
const (
	keychainUnavailableFix = "use the signed vettid-agent app (vettid-agent.app/Contents/MacOS/vettid-agent), or pair with --passphrase (not bound to this computer)"
	keychainLockedFix      = "run the connector as the logged-in user while the Mac is unlocked (not over SSH or from a launch daemon with no one logged in at the Mac)"
	keychainGoneFix        = "if the item was deleted or the file was copied from elsewhere, pair again (`vettid-agent pair --restart`)"
)

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
	// entitled reports whether this process has the
	// keychain-access-groups entitlement.
	entitled() bool
	// add stores key as a generic password in the data protection
	// keychain, ThisDeviceOnly and not synchronizable.
	add(service, account string, key []byte) int32
	// get looks an item up by its account, in the data protection
	// keychain, without any user interface.
	get(account string) (keychainItem, int32)
	// remove deletes every item with this service (account "") or this
	// account (service "").
	remove(service, account string) int32
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
	if !k.ops.entitled() {
		return nil, fmt.Errorf("%w; %s", ErrKeychainUnavailable, keychainUnavailableFix)
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
		k.ops.remove("", name)
		return nil, k.statusError("read back the new key", st, false)
	}
	defer clear(item.data)
	if subtle.ConstantTimeCompare(item.data, kek) != 1 || !item.thisDeviceOnly || item.synchronizable || item.service != k.service {
		k.ops.remove("", name)
		return nil, errors.New("Keychain protector: macOS did not store the key as asked (this Mac only, not synchronized), so it is not used")
	}
	blob := make([]byte, 0, keychainBlobLen)
	blob = append(blob, keychainBlobVersion)
	blob = append(blob, id...)
	blob = append(blob, nonce...)
	aead, err := chacha20poly1305.NewX(kek)
	if err != nil {
		k.ops.remove("", name)
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
	if !k.ops.entitled() {
		return nil, fmt.Errorf("%w, and the state file's key is in the Keychain; use the signed vettid-agent app", ErrKeychainUnavailable)
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
	k.remember(name)
	return key, nil
}

// Wipe deletes this state directory's items, then the items this
// instance wrapped or unwrapped (see the comment at the top of this
// file). Items already gone count as deleted.
func (k *Keychain) Wipe() error {
	if !k.ops.entitled() {
		return fmt.Errorf("%w, so it cannot check for or delete the state file's Keychain item; use the signed vettid-agent app to wipe", ErrKeychainUnavailable)
	}
	if k.dirErr != nil {
		return fmt.Errorf("Keychain protector: the state directory could not be resolved, so its Keychain items cannot be found: %w", k.dirErr)
	}
	// SecItemDelete deletes every match in the data protection keychain;
	// repeat until none is left in case a release deletes one at a time.
	for i := 0; ; i++ {
		st := k.ops.remove(k.service, "")
		if st == errSecItemNotFound {
			break
		}
		if st != errSecSuccess {
			return k.statusError("delete the key", st, false)
		}
		if i == maxKeychainDeletes {
			return errors.New("Keychain protector: the state directory's items are still there after deleting them")
		}
	}
	for len(k.names) > 0 {
		if st := k.ops.remove("", k.names[0]); st != errSecSuccess && st != errSecItemNotFound {
			return k.statusError("delete the key", st, false)
		}
		k.names = k.names[1:]
	}
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
//   - the binary has the entitlement but the Keychain fails (locked, no
//     login session, macOS stored the probe otherwise): an error naming
//     the cause and the fix, unless opts.AllowPassphraseFallback is set
//     (the operator asked for a passphrase), in which case the passphrase
//     protector with that cause as the reason.
func chooseKeychain(ops keychainOps, opts ChooseOptions) (Choice, error) {
	passphrase := func(reason string) Choice {
		return Choice{Protector: PassphraseName, Reason: reason + "; using a passphrase"}
	}
	if !ops.entitled() {
		return passphrase("this vettid-agent build cannot use the macOS Keychain (only the signed vettid-agent app can: run it from vettid-agent.app/Contents/MacOS/vettid-agent to bind keys to this Mac)"), nil
	}
	err := tryKeychain(ops)
	if err == nil {
		return Choice{Protector: KeychainName, Reason: "macOS Keychain, this Mac only", MachineBound: true}, nil
	}
	if opts.AllowPassphraseFallback {
		return passphrase(err.Error()), nil
	}
	return Choice{}, fmt.Errorf("%w; or choose a passphrase instead (not bound to this computer)", err)
}

// tryKeychain wraps, unwraps and wipes a random probe key under the
// probe service (never a state directory's).
func tryKeychain(ops keychainOps) error {
	key := make([]byte, state.DataKeyLen)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	p := newKeychain(ops, keychainProbeName, nil)
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
