//go:build darwin && cgo

package protect

// The macOS Keychain calls for the Keychain protector (keychain.go),
// through the Security framework. Only the data protection keychain is
// used (kSecUseDataProtectionKeychain on every call), never the
// file-based login keychain; no call shows a user interface.
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
enum { vk_nomem = -108, vk_badresult = -2070 };

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

static int vk_entitled(void) {
	SecTaskRef t = SecTaskCreateFromSelf(NULL);
	if (t == NULL) return 0;
	CFTypeRef v = SecTaskCopyValueForEntitlement(t, CFSTR("keychain-access-groups"), NULL);
	CFRelease(t);
	if (v == NULL) return 0;
	int ok = CFGetTypeID(v) == CFArrayGetTypeID() && CFArrayGetCount((CFArrayRef)v) > 0;
	CFRelease(v);
	return ok;
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
	CFDictionarySetValue(q, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
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

static OSStatus vk_remove(const char *service, const char *account) {
	CFMutableDictionaryRef q = vk_query();
	if (q == NULL) return vk_nomem;
	if ((service[0] != 0 && !vk_set_str(q, kSecAttrService, service)) ||
			(account[0] != 0 && !vk_set_str(q, kSecAttrAccount, account))) {
		CFRelease(q);
		return vk_nomem;
	}
	CFDictionarySetValue(q, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
	OSStatus st = SecItemDelete(q);
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
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/vettid/vettid-agent/internal/state"
)

// darwinKeychain is the real keychainOps.
type darwinKeychain struct{}

func (darwinKeychain) entitled() bool { return C.vk_entitled() == 1 }

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

func (darwinKeychain) remove(service, account string) int32 {
	cs, ca := C.CString(service), C.CString(account)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	return int32(C.vk_remove(cs, ca))
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
// same directory gives the same name however it is spelled.
func NewKeychain(dir string) *Keychain {
	canonical, err := canonicalDir(dir)
	if err != nil {
		return newKeychain(keychainOS, "", err)
	}
	return newKeychain(keychainOS, keychainDirService(canonical), nil)
}

// canonicalDir returns the path macOS reports for the open directory
// (fcntl F_GETPATH), or, when the directory cannot be opened, its
// absolute path with symbolic links resolved.
func canonicalDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("no state directory")
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err == nil {
		defer unix.Close(fd)
		getpathMu.Lock()
		defer getpathMu.Unlock()
		_, err = unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&getpathBuf[0]))))
		if err == nil {
			n := 0
			for n < len(getpathBuf) && getpathBuf[n] != 0 {
				n++
			}
			p := string(getpathBuf[:n])
			clear(getpathBuf[:])
			if p != "" {
				return p, nil
			}
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("the state directory's absolute path: %w", err)
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r, nil
	}
	return filepath.Clean(abs), nil
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
// protector cannot be determined. The passphrase instance holds no
// passphrase: it can only Wipe (which deletes nothing). The Keychain
// instance's Wipe deletes dir's items; in a build without the Keychain
// entitlement it cannot look, and says so.
func All(dir string) []state.Protector {
	return []state.Protector{NewKeychain(dir), &Passphrase{}}
}
