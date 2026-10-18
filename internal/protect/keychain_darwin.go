//go:build darwin && cgo

package protect

// The macOS Keychain calls for the Keychain protector (keychain.go),
// through the Security framework. Only the data protection keychain is
// used (kSecUseDataProtectionKeychain on every call), never the
// file-based login keychain. The items carry no access control object
// (kSecAttrAccessControl), only an accessibility class, so the data
// protection keychain never shows a prompt for them.
//
// The KEK passes through CoreFoundation objects (CFData) that the
// framework allocates and frees; they cannot be cleared from here. The
// Go copies are cleared when no longer needed (best effort, as in
// internal/state).

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// vk_nomem is returned when a CoreFoundation object cannot be made
// (memFullErr); vk_badresult when the Keychain answers in a form not
// asked for (errSecInternalComponent).
// vk_badparam (errSecParam) when an argument would widen a query (an
// empty service or account); vk_toomany (errSecBufferTooSmall) when a
// listing has more items than the caller has room for.
enum { vk_nomem = -108, vk_badresult = -2070, vk_badparam = -50, vk_toomany = -25301 };

static CFMutableDictionaryRef vk_query(void) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (q == NULL) return NULL;
	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(q, kSecUseDataProtectionKeychain, kCFBooleanTrue);
	return q;
}

static int vk_set_str(CFMutableDictionaryRef q, CFStringRef key, const char *v) {
	CFStringRef s = CFStringCreateWithCString(NULL, v, kCFStringEncodingUTF8);
	if (s == NULL) return 0;
	CFDictionarySetValue(q, key, s);
	CFRelease(s);
	return 1;
}

// vk_entitlement: 1 present, 0 absent, -1 could not be read (no task
// object, an error from the framework, or a value of another form).
static int vk_entitlement(void) {
	SecTaskRef t = SecTaskCreateFromSelf(NULL);
	if (t == NULL) return -1;
	CFErrorRef err = NULL;
	CFTypeRef v = SecTaskCopyValueForEntitlement(t, CFSTR("keychain-access-groups"), &err);
	CFRelease(t);
	if (v == NULL) {
		if (err != NULL) {
			CFRelease(err);
			return -1;
		}
		return 0;
	}
	if (err != NULL) CFRelease(err);
	int ok = CFGetTypeID(v) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)v) > 0;
	CFRelease(v);
	return ok ? 1 : -1;
}

static OSStatus vk_add(const char *service, const char *account, const char *label,
		const unsigned char *key, int keylen) {
	CFMutableDictionaryRef q = vk_query();
	if (q == NULL) return vk_nomem;
	CFDataRef d = CFDataCreate(NULL, key, keylen);
	if (d == NULL || !vk_set_str(q, kSecAttrService, service) ||
			!vk_set_str(q, kSecAttrAccount, account) || !vk_set_str(q, kSecAttrLabel, label)) {
		if (d != NULL) CFRelease(d);
		CFRelease(q);
		return vk_nomem;
	}
	CFDictionarySetValue(q, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	CFDictionarySetValue(q, kSecAttrSynchronizable, kCFBooleanFalse);
	CFDictionarySetValue(q, kSecValueData, d);
	OSStatus st = SecItemAdd(q, NULL);
	CFRelease(d);
	CFRelease(q);
	return st;
}

// vk_truthy reads a boolean attribute (CFBoolean or CFNumber); a value
// of another type counts as true, so that it is refused.
static int vk_truthy(CFTypeRef v) {
	if (v == NULL) return 0;
	if (CFGetTypeID(v) == CFBooleanGetTypeID()) return CFBooleanGetValue((CFBooleanRef)v) ? 1 : 0;
	if (CFGetTypeID(v) == CFNumberGetTypeID()) {
		long long n = 1;
		if (!CFNumberGetValue((CFNumberRef)v, kCFNumberLongLongType, &n)) return 1;
		return n != 0;
	}
	return 1;
}

static OSStatus vk_get(const char *account, unsigned char *out, int outcap, int *outlen,
		int *thisDeviceOnly, int *sync, char *service, int servicecap) {
	*outlen = -1;
	*thisDeviceOnly = 0;
	*sync = 1;
	service[0] = 0;
	CFMutableDictionaryRef q = vk_query();
	if (q == NULL) return vk_nomem;
	if (!vk_set_str(q, kSecAttrAccount, account)) {
		CFRelease(q);
		return vk_nomem;
	}
	CFDictionarySetValue(q, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFTypeRef r = NULL;
	OSStatus st = SecItemCopyMatching(q, &r);
	CFRelease(q);
	if (st != errSecSuccess) {
		if (r != NULL) CFRelease(r);
		return st;
	}
	if (r == NULL || CFGetTypeID(r) != CFDictionaryGetTypeID()) {
		if (r != NULL) CFRelease(r);
		return vk_badresult;
	}
	CFDictionaryRef m = (CFDictionaryRef)r;
	CFTypeRef acc = CFDictionaryGetValue(m, kSecAttrAccessible);
	*thisDeviceOnly = acc != NULL && CFEqual(acc, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	*sync = vk_truthy(CFDictionaryGetValue(m, kSecAttrSynchronizable));
	CFTypeRef sv = CFDictionaryGetValue(m, kSecAttrService);
	if (sv != NULL && CFGetTypeID(sv) == CFStringGetTypeID()) {
		if (!CFStringGetCString((CFStringRef)sv, service, servicecap, kCFStringEncodingUTF8)) service[0] = 0;
	}
	CFTypeRef d = CFDictionaryGetValue(m, kSecValueData);
	if (d == NULL || CFGetTypeID(d) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)d) > outcap) {
		CFRelease(r);
		return vk_badresult;
	}
	*outlen = (int)CFDataGetLength((CFDataRef)d);
	memcpy(out, CFDataGetBytePtr((CFDataRef)d), *outlen);
	CFRelease(r);
	return errSecSuccess;
}

// vk_list writes the accounts (slots of slotlen bytes) and creation
// times of the items with this service, at most cap of them.
static OSStatus vk_list(const char *service, char *accounts, int slotlen, double *created, int cap, int *n) {
	*n = 0;
	if (service == NULL || service[0] == 0) return vk_badparam;
	CFMutableDictionaryRef q = vk_query();
	if (q == NULL) return vk_nomem;
	if (!vk_set_str(q, kSecAttrService, service)) {
		CFRelease(q);
		return vk_nomem;
	}
	CFDictionarySetValue(q, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
	CFTypeRef r = NULL;
	OSStatus st = SecItemCopyMatching(q, &r);
	CFRelease(q);
	if (st != errSecSuccess) {
		if (r != NULL) CFRelease(r);
		return st;
	}
	if (r == NULL || CFGetTypeID(r) != CFArrayGetTypeID()) {
		if (r != NULL) CFRelease(r);
		return vk_badresult;
	}
	CFArrayRef a = (CFArrayRef)r;
	CFIndex count = CFArrayGetCount(a);
	if (count > cap) {
		CFRelease(r);
		return vk_toomany;
	}
	for (CFIndex i = 0; i < count; i++) {
		CFTypeRef m = CFArrayGetValueAtIndex(a, i);
		char *slot = accounts + i * slotlen;
		slot[0] = 0;
		created[i] = 0;
		if (m == NULL || CFGetTypeID(m) != CFDictionaryGetTypeID()) {
			CFRelease(r);
			return vk_badresult;
		}
		CFTypeRef ac = CFDictionaryGetValue((CFDictionaryRef)m, kSecAttrAccount);
		if (ac == NULL || CFGetTypeID(ac) != CFStringGetTypeID() ||
				!CFStringGetCString((CFStringRef)ac, slot, slotlen, kCFStringEncodingUTF8) || slot[0] == 0) {
			CFRelease(r);
			return vk_badresult;
		}
		CFTypeRef cd = CFDictionaryGetValue((CFDictionaryRef)m, kSecAttrCreationDate);
		if (cd != NULL && CFGetTypeID(cd) == CFDateGetTypeID()) created[i] = CFDateGetAbsoluteTime((CFDateRef)cd);
	}
	*n = (int)count;
	CFRelease(r);
	return errSecSuccess;
}

// vk_account_query is a query for the one item with this account
// (never empty: a query without it would match every item).
static CFMutableDictionaryRef vk_account_query(const char *account, OSStatus *st) {
	if (account == NULL || account[0] == 0) {
		*st = vk_badparam;
		return NULL;
	}
	CFMutableDictionaryRef q = vk_query();
	if (q == NULL || !vk_set_str(q, kSecAttrAccount, account)) {
		if (q != NULL) CFRelease(q);
		*st = vk_nomem;
		return NULL;
	}
	CFDictionarySetValue(q, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
	return q;
}

static OSStatus vk_retag(const char *account, const char *service) {
	if (service == NULL || service[0] == 0) return vk_badparam;
	OSStatus st = errSecSuccess;
	CFMutableDictionaryRef q = vk_account_query(account, &st);
	if (q == NULL) return st;
	CFMutableDictionaryRef u = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (u == NULL || !vk_set_str(u, kSecAttrService, service)) {
		if (u != NULL) CFRelease(u);
		CFRelease(q);
		return vk_nomem;
	}
	st = SecItemUpdate(q, u);
	CFRelease(u);
	CFRelease(q);
	return st;
}

static OSStatus vk_remove(const char *account) {
	OSStatus st = errSecSuccess;
	CFMutableDictionaryRef q = vk_account_query(account, &st);
	if (q == NULL) return st;
	st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

static int vk_message(OSStatus st, char *out, int outcap) {
	out[0] = 0;
	CFStringRef s = SecCopyErrorMessageString(st, NULL);
	if (s == NULL) return 0;
	int ok = CFStringGetCString(s, out, outcap, kCFStringEncodingUTF8);
	CFRelease(s);
	return ok;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/vettid/vettid-agent/internal/state"
)

// darwinKeychain is the real keychainOps.
type darwinKeychain struct{}

func (darwinKeychain) entitlement() int { return int(C.vk_entitlement()) }

func (darwinKeychain) add(service, account string, key []byte) int32 {
	if len(key) == 0 {
		return int32(C.vk_nomem)
	}
	cs, ca, cl := C.CString(service), C.CString(account), C.CString(keychainLabel)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cl))
	return int32(C.vk_add(cs, ca, cl, (*C.uchar)(unsafe.Pointer(&key[0])), C.int(len(key))))
}

func (darwinKeychain) get(account string) (keychainItem, int32) {
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	var out [64]byte
	defer clear(out[:])
	var service [256]byte
	var n, tdo, sync C.int
	st := int32(C.vk_get(ca, (*C.uchar)(unsafe.Pointer(&out[0])), C.int(len(out)), &n,
		&tdo, &sync, (*C.char)(unsafe.Pointer(&service[0])), C.int(len(service))))
	if st != errSecSuccess {
		return keychainItem{}, st
	}
	return keychainItem{
		data:           append([]byte(nil), out[:n]...),
		service:        C.GoString((*C.char)(unsafe.Pointer(&service[0]))),
		thisDeviceOnly: tdo == 1,
		synchronizable: sync != 0,
	}, st
}

// keychainListMax bounds a listing; a state directory has one item in
// normal use.
const (
	keychainListMax = 256
	keychainSlotLen = 128
)

func (darwinKeychain) list(service string) ([]keychainListed, int32) {
	if service == "" {
		return nil, int32(C.vk_badparam)
	}
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	accounts := make([]byte, keychainListMax*keychainSlotLen)
	created := make([]C.double, keychainListMax)
	var n C.int
	st := int32(C.vk_list(cs, (*C.char)(unsafe.Pointer(&accounts[0])), keychainSlotLen,
		&created[0], keychainListMax, &n))
	if st != errSecSuccess {
		return nil, st
	}
	out := make([]keychainListed, 0, int(n))
	for i := 0; i < int(n); i++ {
		slot := accounts[i*keychainSlotLen : (i+1)*keychainSlotLen]
		out = append(out, keychainListed{
			account: C.GoString((*C.char)(unsafe.Pointer(&slot[0]))),
			created: float64(created[i]),
		})
	}
	return out, st
}

func (darwinKeychain) retag(account, service string) int32 {
	if account == "" || service == "" {
		return int32(C.vk_badparam)
	}
	ca, cs := C.CString(account), C.CString(service)
	defer C.free(unsafe.Pointer(ca))
	defer C.free(unsafe.Pointer(cs))
	return int32(C.vk_retag(ca, cs))
}

func (darwinKeychain) remove(account string) int32 {
	if account == "" {
		return int32(C.vk_badparam)
	}
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	return int32(C.vk_remove(ca))
}

// cEmptyQueryStatuses calls the C functions directly with an empty
// account or service, past the Go guards, so that a test shows the C
// guards refuse them (errSecParam) without asking the Keychain.
func cEmptyQueryStatuses() (remove, list, retag int32) {
	empty, svc := C.CString(""), C.CString(keychainProbeName+"guard")
	defer C.free(unsafe.Pointer(empty))
	defer C.free(unsafe.Pointer(svc))
	var acc [keychainSlotLen]byte
	var created C.double
	var n C.int
	remove = int32(C.vk_remove(empty))
	list = int32(C.vk_list(empty, (*C.char)(unsafe.Pointer(&acc[0])), keychainSlotLen, &created, 1, &n))
	retag = int32(C.vk_retag(empty, svc))
	return remove, list, retag
}

func (darwinKeychain) message(st int32) string {
	var out [512]byte
	if C.vk_message(C.OSStatus(st), (*C.char)(unsafe.Pointer(&out[0])), C.int(len(out))) == 0 {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(&out[0])))
}

// keychainOS is the Keychain ChooseProtector and NewKeychain use; tests
// replace it.
var keychainOS keychainOps = darwinKeychain{}

// NewKeychain returns the Keychain protector for the state directory
// dir. The directory's items are named by its canonical path (symbolic
// links resolved, and the letter case the file system stores), so the
// same directory gives the same name however it is spelled. If dir
// cannot be resolved, Wrap and Wipe refuse; Unwrap still opens by the
// item's name (without re-tagging).
func NewKeychain(dir string) *Keychain {
	canonical, err := canonicalDir(dir)
	if err != nil {
		return newKeychain(keychainOS, "", err)
	}
	return newKeychain(keychainOS, keychainDirService(canonical), nil)
}

// canonicalDir returns the path macOS reports for the open directory
// (fcntl F_GETPATH). A directory that cannot be opened, or whose path
// macOS does not report, is an error, never a guess: a path that is not
// canonical would name other Keychain items than the directory's.
func canonicalDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("no state directory")
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", fmt.Errorf("open the state directory: %w", err)
	}
	defer unix.Close(fd)
	getpathMu.Lock()
	defer getpathMu.Unlock()
	defer clear(getpathBuf[:])
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&getpathBuf[0])))); err != nil {
		return "", fmt.Errorf("the state directory's path (F_GETPATH): %w", err)
	}
	n := 0
	for n < len(getpathBuf) && getpathBuf[n] != 0 {
		n++
	}
	if n == 0 || getpathBuf[0] != '/' {
		return "", errors.New("the state directory's path (F_GETPATH) is not absolute")
	}
	return string(getpathBuf[:n]), nil
}

// ChooseProtector picks the protector for a new state file (AGENT-PLAN
// §2 AG3; chooseKeychain has the rules).
func ChooseProtector(opts ChooseOptions) (Choice, error) {
	return chooseKeychain(keychainOS, opts)
}

// Platform returns the platform protector named name (a state file
// header's protector, or Choice.Protector) for the state directory dir,
// or nil if this build has no platform protector of that name. The
// passphrase protector is not a platform protector: it needs the
// passphrase (NewPassphrase).
func Platform(name, dir string) state.Protector {
	if name == KeychainName {
		return NewKeychain(dir)
	}
	return nil
}

// All returns one instance of every protector this build knows, for
// state.Store.WipeAll on the state directory dir when a state file's
// protector cannot be determined: the Keychain protector, which deletes
// dir's items, unless this build certainly lacks the entitlement
// (keychainProtectors says why), and the passphrase protector, which
// holds no passphrase and can only Wipe (deleting nothing).
func All(dir string) []state.Protector {
	return keychainProtectors(keychainOS, NewKeychain(dir))
}
