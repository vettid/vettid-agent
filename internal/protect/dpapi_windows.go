//go:build windows

package protect

// The Windows DPAPI protector (AGENT-PLAN §2 AG3, §4.2, §6 A1.4). The
// data key is encrypted with CryptProtectData in user scope: Windows
// derives the key from the current user's DPAPI master key, which is
// itself protected by the user's logon credentials, so the state file's
// key opens only for this Windows user on this computer (LEASH §3.4),
// with the exceptions below.
//
// Construction:
//
//   - CryptProtectData / CryptUnprotectData with
//     CRYPTPROTECT_UI_FORBIDDEN and never CRYPTPROTECT_LOCAL_MACHINE
//     (machine scope would let every user of the computer open it; a
//     machine-scope blob is refused before Windows is asked).
//   - Optional entropy: the public constant dpapiEntropyLabel. It keeps
//     this protector's blobs apart from other programs' DPAPI blobs; it
//     is not a secret, and it does not protect against another process
//     running as the same user, which can call CryptUnprotectData with
//     the same constant. What protects the state file from such a
//     process is nothing here: the same user's processes can read the
//     state file and use DPAPI (AGENT-PLAN §10).
//   - The description dpapiDescription, stored in the clear in the
//     blob, and checked on both sides.
//   - The plaintext is the data key and a check value (dpapi_blob.go).
//   - Buffers Windows returns are freed with LocalFree; the decrypted
//     buffer is zeroed before it is freed, and the plaintext copies made
//     here are cleared when no longer needed (best effort, as in
//     internal/state).
//
// The wrapped blob and its checks are in dpapi_blob.go.
//
// What user scope does not give (said in the README): a user with a
// roaming profile can open the file on another computer of the domain
// where the profile is loaded (Microsoft's CryptProtectData remarks), and
// in an Active Directory domain the domain's DPAPI backup key, held by
// the domain controllers, can recover a domain user's master keys. For a
// local account or a Microsoft account without roaming, the file opens
// only on this computer.
//
// Errors are of three kinds. Definite: ErrDPAPIRefused
// (ERROR_INVALID_DATA, NTE_BAD_DATA, ERROR_PASSWORD_RESTRICTION: the
// blob's integrity check failed, so it was altered or made with other
// entropy; or what DPAPI returned is not this protector's key) and
// ErrDPAPIKeyLost (NTE_BAD_KEY_STATE: Windows could not use the master
// key the blob names). The Windows CI job shows NTE_BAD_KEY_STATE both
// for another local user's blob (in either direction) and for the
// user's own blob after an administrator reset the password; whether
// the master key file is in this user's profile tells the two apart
// for the message (keyLostHint). Environmental: ErrDPAPIProfile (no
// loaded profile, or a logon without the user's password). Anything
// else keeps its cause.
//
// Wipe deletes nothing: the DPAPI blob lives only in the state file;
// Windows keeps no per-blob key, and the user's master keys belong to
// the user, not to this program. So `forget` destroys the wrapped key by
// overwriting and deleting the file. An old copy of the state file
// recovered from the disk afterwards (a backup, a file system snapshot,
// a block an SSD remapped) can still be opened by this Windows user on
// this computer (or wherever the user's DPAPI master keys are
// available) for as long as the user's master keys exist. Opening such
// a copy needs the copy (from a backup, a snapshot or the raw disk) and
// this user's logon (or the user's credentials and master key files).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/vettid/vettid-agent/internal/state"
)

// DPAPI is the DPAPI protector (user scope). It holds no state.
type DPAPI struct{}

var _ state.Protector = DPAPI{}

// NewDPAPI returns the DPAPI protector.
func NewDPAPI() DPAPI { return DPAPI{} }

// Name returns "dpapi".
func (DPAPI) Name() string { return DPAPIName }

// Wipe does nothing: the wrapped key exists only in the state file, and
// an old copy of that file recovered from the disk still opens for this
// Windows user (see the comment at the top of this file).
func (DPAPI) Wipe() error { return nil }

// The DPAPI calls; tests replace them to inject Windows answers.
var (
	cryptProtect   = windows.CryptProtectData
	cryptUnprotect = windows.CryptUnprotectData
)

// dpapiFlags are the flags for both calls.
const dpapiFlags = windows.CRYPTPROTECT_UI_FORBIDDEN

func dataBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// freeHook is called just before a buffer is freed; tests use it.
var freeHook = func(*byte, uint32) {}

// takeBlob copies a buffer Windows allocated, zeroes it and frees it.
func takeBlob(b *windows.DataBlob) []byte {
	if b.Data == nil {
		return nil
	}
	buf := unsafe.Slice(b.Data, b.Size)
	out := append([]byte(nil), buf...)
	clear(buf)
	freeHook(b.Data, b.Size)
	windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	b.Data, b.Size = nil, 0
	return out
}

// Wrap encrypts dataKey with DPAPI for the current user.
func (DPAPI) Wrap(dataKey []byte) ([]byte, error) {
	if len(dataKey) != state.DataKeyLen {
		return nil, errors.New("DPAPI protector: data key length")
	}
	plain := dpapiPlaintext(dataKey)
	defer clear(plain)
	desc, err := windows.UTF16PtrFromString(dpapiDescription)
	if err != nil {
		return nil, err
	}
	entropy := []byte(dpapiEntropyLabel)
	var out windows.DataBlob
	if err := cryptProtect(dataBlob(plain), desc, dataBlob(entropy), 0, nil, dpapiFlags, &out); err != nil {
		return nil, classifyDPAPI("protect the key", err, nil)
	}
	inner := takeBlob(&out)
	if _, err := checkDPAPIInner(inner); err != nil {
		// Windows wrote a blob this protector would refuse to read
		// (another layout, a policy that picks other algorithms).
		return nil, fmt.Errorf("DPAPI protector: Windows returned a blob in a form this version does not accept (%w)", err)
	}
	return encodeDPAPIBlob(inner), nil
}

// Unwrap checks the blob's format and decrypts it with DPAPI.
func (DPAPI) Unwrap(blob []byte) ([]byte, error) {
	inner, info, err := decodeDPAPIBlob(blob)
	if err != nil {
		return nil, err
	}
	entropy := []byte(dpapiEntropyLabel)
	var out windows.DataBlob
	var desc *uint16
	err = cryptUnprotect(dataBlob(inner), &desc, dataBlob(entropy), 0, nil, dpapiFlags, &out)
	descStr := ""
	if desc != nil {
		descStr = windows.UTF16PtrToString(desc)
		windows.LocalFree(windows.Handle(unsafe.Pointer(desc)))
	}
	if err != nil {
		return nil, classifyDPAPI("open the key", err, &info)
	}
	plain := takeBlob(&out)
	defer clear(plain)
	if descStr != dpapiDescription {
		return nil, ErrDPAPIRefused
	}
	return dpapiKeyFromPlaintext(plain)
}

// classifyDPAPI maps a DPAPI failure to a definite, environmental or
// other error, with the fix. info, when known, refines the message for
// a key Windows could not use.
func classifyDPAPI(step string, err error, info *dpapiInfo) error {
	var errno windows.Errno
	if !errors.As(err, &errno) {
		return fmt.Errorf("DPAPI: %s: %w", step, err)
	}
	switch uint32(errno) {
	case uint32(windows.ERROR_INVALID_DATA), uint32(windows.NTE_BAD_DATA),
		uint32(windows.ERROR_PASSWORD_RESTRICTION):
		return fmt.Errorf("%w (%s)", ErrDPAPIRefused, codeOf(errno))
	case uint32(windows.NTE_BAD_KEY_STATE):
		return fmt.Errorf("%w: %s (%s)", ErrDPAPIKeyLost, keyLostHint(info), codeOf(errno))
	case uint32(windows.ERROR_FILE_NOT_FOUND), uint32(windows.ERROR_PATH_NOT_FOUND),
		uint32(windows.ERROR_NO_SUCH_LOGON_SESSION), uint32(windows.ERROR_NOT_FOUND):
		return fmt.Errorf("%w; run the connector in a logon with the user's password and a loaded profile (not a service or scheduled task without a loaded profile or a stored password); with a roaming profile, wait until the profile is available (%s)", ErrDPAPIProfile, codeOf(errno))
	default:
		return fmt.Errorf("DPAPI: %s: %s", step, codeOf(errno))
	}
}

func codeOf(e windows.Errno) string {
	return fmt.Sprintf("Windows error 0x%08X: %v", uint32(e), e)
}

// keyLostHint says which case NTE_BAD_KEY_STATE is most likely, from
// whether the blob's master key file exists in this user's profile
// (%APPDATA%\Microsoft\Protect\<SID>\<GUID>; a layout Windows does not
// document, so this is a hint only: it never changes the error's kind).
func keyLostHint(info *dpapiInfo) string {
	const reset = "if an administrator reset this user's password (rather than the user changing it), Windows can no longer use the keys made before; set the old password back if you can, or pair again (`vettid-agent forget`, then `pair`)"
	const other = "the state file was made by another Windows user or on another computer (or this user's profile was recreated); run the connector as the user who paired it, or pair again (`vettid-agent forget`, then `pair`)"
	if info == nil {
		return reset + "; or " + other
	}
	switch masterKeyPresent(*info) {
	case 1:
		return reset
	case 0:
		return other
	default:
		return reset + "; or " + other
	}
}

// masterKeyPresent reports 1 if the blob's master key file is in this
// user's profile, 0 if it is not, -1 if that cannot be told.
func masterKeyPresent(info dpapiInfo) int {
	sid, err := currentSID()
	if err != nil {
		return -1
	}
	appData, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil {
		return -1
	}
	dir := filepath.Join(appData, "Microsoft", "Protect", sid)
	if _, err := os.Lstat(dir); err != nil {
		return -1
	}
	_, err = os.Lstat(filepath.Join(dir, info.masterKeyGUID()))
	switch {
	case err == nil:
		return 1
	case errors.Is(err, os.ErrNotExist):
		return 0
	default:
		return -1
	}
}

func currentSID() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}
