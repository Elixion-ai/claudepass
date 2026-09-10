//go:build darwin && touchid && cgo

package broker

// This file is the cgo build path for CLA-23: it links the Security
// framework directly (unlike keychain_darwin.go, which shells out to the
// `security` CLI precisely so a normal build never links it or risks
// popping the Keychain's access-control GUI) so it can set a
// SecAccessControl the CLI tool has no flag for. It only compiles when a
// binary is deliberately built with `-tags touchid` on darwin with cgo
// enabled (CGO_ENABLED=1) — never in the default CGO_ENABLED=0 build that
// every release and CI run uses (see ADR-0007, and touchid_stub.go for
// every other configuration).

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unsafe"
)

const touchIDBuildSupported = true

// cfPtr converts a cgo CoreFoundation reference to unsafe.Pointer. cgo
// represents every Objective-C-bridged CF opaque type this file touches
// (CFTypeRef, CFStringRef, CFDictionaryRef, SecAccessControlRef, and
// friends) as a plain uintptr rather than a Go pointer type — deliberately,
// so Go's garbage collector never mistakes a Core Foundation object
// address for a Go heap pointer. Bridging one back to unsafe.Pointer to
// hand it to CFDictionaryCreate is the intended, necessary way to call
// these APIs from cgo: it is not arithmetic on a Go-managed allocation, so
// go vet's unsafeptr heuristic (which cannot tell the two apart) does not
// apply here in spirit even where it might fire in the letter. Two named
// CF types always share the same underlying uintptr representation, so
// converting directly between them (e.g. C.CFTypeRef(cfDataRef)) needs no
// such bridge — cfPtr exists only for the *unsafe.Pointer CFDictionaryCreate
// itself requires.
func cfPtr[T ~uintptr](x T) unsafe.Pointer { return unsafe.Pointer(uintptr(x)) }

// stringToCF creates a CFStringRef from a Go string. The caller must
// CFRelease it.
func stringToCF(s string) C.CFStringRef {
	cstr := C.CString(s)
	defer C.free(unsafe.Pointer(cstr))
	return C.CFStringCreateWithCString(C.kCFAllocatorDefault, cstr, C.kCFStringEncodingUTF8)
}

// cfStringToGo converts a CFStringRef to a Go string. It does not release
// s; the caller owns that.
func cfStringToGo(s C.CFStringRef) string {
	if s == 0 {
		return ""
	}
	if cstr := C.CFStringGetCStringPtr(s, C.kCFStringEncodingUTF8); cstr != nil {
		return C.GoString(cstr)
	}
	n := C.CFStringGetLength(s)
	maxLen := C.CFStringGetMaximumSizeForEncoding(n, C.kCFStringEncodingUTF8) + 1
	buf := make([]byte, int(maxLen))
	ok := C.CFStringGetCString(s, (*C.char)(unsafe.Pointer(&buf[0])), maxLen, C.kCFStringEncodingUTF8)
	if ok == 0 {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
}

// secErrString renders an OSStatus (from SecItemAdd/SecItemDelete/
// SecItemCopyMatching) as a human-readable message.
func secErrString(status C.OSStatus) string {
	msg := C.SecCopyErrorMessageString(status, nil)
	if msg == 0 {
		return fmt.Sprintf("OSStatus %d", int(status))
	}
	defer C.CFRelease(C.CFTypeRef(msg))
	return fmt.Sprintf("%s (OSStatus %d)", cfStringToGo(msg), int(status))
}

// cfErrString renders a CFErrorRef (from SecAccessControlCreateWithFlags)
// as a human-readable message. It releases cferr.
func cfErrString(cferr C.CFErrorRef) string {
	if cferr == 0 {
		return "unknown error"
	}
	defer C.CFRelease(C.CFTypeRef(cferr))
	desc := C.CFErrorCopyDescription(cferr)
	if desc == 0 {
		return "unknown error"
	}
	defer C.CFRelease(C.CFTypeRef(desc))
	return cfStringToGo(desc)
}

// newCFDict builds a CFDictionary (kCFTypeDictionaryKeyCallBacks/
// kCFTypeDictionaryValueCallBacks) from alternating key, value pairs. The
// caller must CFRelease the result.
func newCFDict(pairs ...unsafe.Pointer) C.CFDictionaryRef {
	n := len(pairs) / 2
	keys := make([]unsafe.Pointer, n)
	vals := make([]unsafe.Pointer, n)
	for i := 0; i < n; i++ {
		keys[i] = pairs[2*i]
		vals[i] = pairs[2*i+1]
	}
	return C.CFDictionaryCreate(
		C.kCFAllocatorDefault,
		&keys[0], &vals[0],
		C.CFIndex(n),
		&C.kCFTypeDictionaryKeyCallBacks,
		&C.kCFTypeDictionaryValueCallBacks,
	)
}

// itemQuery builds the (kSecClass, kSecAttrService, kSecAttrAccount)
// dictionary identifying one generic-password item. The caller must
// CFRelease the result (but not cfService/cfAccount, which it borrows).
//
// This, and every other dictionary in this file, deliberately leaves
// kSecUseDataProtectionKeychain unset rather than forcing it false: this
// file needs the platform default it already resolves to on every
// supported macOS version — the Data Protection Keychain — because
// kSecAttrAccessControl / kSecAccessControlUserPresence is only enforced
// there at all. The legacy, file-based keychain accepts a SecAccessControl
// attribute on an item without complaint but silently does not enforce
// it — confirmed with the no-UI probe in touchid_darwin_test.go before
// settling on this design, since shipping a "Touch ID" flag that quietly
// protects nothing would be worse than not offering one. The Data
// Protection Keychain is also where `security`(1) — and so
// keychain_darwin.go's cgo-free keychainGet/keychainSet — already look by
// default, so cross-compatibility holds without needing this key either.
func itemQuery(cfService, cfAccount C.CFStringRef) C.CFDictionaryRef {
	return newCFDict(
		cfPtr(C.kSecClass), cfPtr(C.kSecClassGenericPassword),
		cfPtr(C.kSecAttrService), cfPtr(cfService),
		cfPtr(C.kSecAttrAccount), cfPtr(cfAccount),
	)
}

// keychainSetUserPresence is SetKeychainKeyUserPresence's implementation:
// see its doc comment in touchid.go for the full contract. It deletes any
// existing (service, account) item first, since SecItemAdd refuses a
// duplicate, then adds a new one carrying a SecAccessControl that requires
// kSecAccessControlUserPresence, storing key base64-encoded — byte-for-byte
// what keychainSet (keychain_darwin.go) would have stored, so that plain,
// cgo-free function still decodes this item correctly.
func keychainSetUserPresence(service, account string, key []byte) error {
	cfService := stringToCF(service)
	defer C.CFRelease(C.CFTypeRef(cfService))
	cfAccount := stringToCF(account)
	defer C.CFRelease(C.CFTypeRef(cfAccount))

	delQuery := itemQuery(cfService, cfAccount)
	status := C.SecItemDelete(delQuery)
	C.CFRelease(C.CFTypeRef(delQuery))
	if status != C.errSecSuccess && status != C.errSecItemNotFound {
		return fmt.Errorf("broker: SecItemDelete (existing Keychain item): %s", secErrString(status))
	}

	var cferr C.CFErrorRef
	access := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
		C.kSecAccessControlUserPresence,
		&cferr,
	)
	if access == 0 {
		return fmt.Errorf("broker: SecAccessControlCreateWithFlags: %s", cfErrString(cferr))
	}
	defer C.CFRelease(C.CFTypeRef(access))

	enc := []byte(base64.StdEncoding.EncodeToString(key))
	cfData := C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&enc[0])), C.CFIndex(len(enc)))
	if cfData == 0 {
		return fmt.Errorf("broker: CFDataCreate failed for the Vault key")
	}
	defer C.CFRelease(C.CFTypeRef(cfData))

	addQuery := newCFDict(
		cfPtr(C.kSecClass), cfPtr(C.kSecClassGenericPassword),
		cfPtr(C.kSecAttrService), cfPtr(cfService),
		cfPtr(C.kSecAttrAccount), cfPtr(cfAccount),
		cfPtr(C.kSecValueData), cfPtr(cfData),
		cfPtr(C.kSecAttrAccessControl), cfPtr(access),
	)
	defer C.CFRelease(C.CFTypeRef(addQuery))

	status = C.SecItemAdd(addQuery, nil)
	if status == C.errSecMissingEntitlement {
		return fmt.Errorf("broker: SecItemAdd (user-presence Keychain item): %s — this cpass binary needs to be "+
			"code-signed with a keychain-access-groups entitlement matching its Team ID before it can create a "+
			"Touch ID-protected Keychain item (an ad hoc or unsigned build, including a plain `go build -tags "+
			"touchid`, cannot); see docs/SECURITY.md", secErrString(status))
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("broker: SecItemAdd (user-presence Keychain item): %s", secErrString(status))
	}
	return nil
}

// keychainGetUserPresence is GetKeychainKeyUserPresence's implementation:
// see its doc comment in touchid.go. Unlike queryNoUI below (used only to
// prove the ACL is enforced, without ever popping a real prompt), this
// allows the Security framework's normal authentication UI (Touch ID or
// passcode) to appear — it is meant to be called by a human, deliberately,
// never by an automated test.
func keychainGetUserPresence(service, account string) ([]byte, error) {
	cfService := stringToCF(service)
	defer C.CFRelease(C.CFTypeRef(cfService))
	cfAccount := stringToCF(account)
	defer C.CFRelease(C.CFTypeRef(cfAccount))
	prompt := stringToCF("unlock the ClaudePass Vault key")
	defer C.CFRelease(C.CFTypeRef(prompt))

	query := newCFDict(
		cfPtr(C.kSecClass), cfPtr(C.kSecClassGenericPassword),
		cfPtr(C.kSecAttrService), cfPtr(cfService),
		cfPtr(C.kSecAttrAccount), cfPtr(cfAccount),
		cfPtr(C.kSecReturnData), cfPtr(C.kCFBooleanTrue),
		cfPtr(C.kSecMatchLimit), cfPtr(C.kSecMatchLimitOne),
		cfPtr(C.kSecUseOperationPrompt), cfPtr(prompt),
	)
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status != C.errSecSuccess {
		return nil, fmt.Errorf("broker: SecItemCopyMatching %s/%s: %s", service, account, secErrString(status))
	}
	defer C.CFRelease(result)

	data := C.CFDataRef(result)
	n := int(C.CFDataGetLength(data))
	ptr := C.CFDataGetBytePtr(data)
	raw := C.GoBytes(unsafe.Pointer(ptr), C.int(n))

	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("broker: Keychain item %s/%s is not a valid key: %w", service, account, err)
	}
	return key, nil
}

// queryNoUI reads the (service, account) generic-password item with
// kSecUseAuthenticationUISkip: it must never show, or wait on, the real
// Keychain access-control UI, so it is always safe to call from a test —
// unlike keychainGetUserPresence above, which this deliberately does not
// call. It exists for touchid_darwin_test.go's non-interactive proof that
// SetKeychainKeyUserPresence's item is actually access-controlled (see
// that file's package doc comment for the full explanation); it lives
// here, not there, because cgo (`import "C"`) is not supported directly in
// a _test.go file — go build and go test both refuse it outright, vet or
// no vet. The boundary types (bool/string/[]byte, not any cgo-generated
// type) are deliberate, for the same reason.
func queryNoUI(service, account string) (ok bool, statusDesc string, data []byte) {
	cfService := stringToCF(service)
	defer C.CFRelease(C.CFTypeRef(cfService))
	cfAccount := stringToCF(account)
	defer C.CFRelease(C.CFTypeRef(cfAccount))

	query := newCFDict(
		cfPtr(C.kSecClass), cfPtr(C.kSecClassGenericPassword),
		cfPtr(C.kSecAttrService), cfPtr(cfService),
		cfPtr(C.kSecAttrAccount), cfPtr(cfAccount),
		cfPtr(C.kSecReturnData), cfPtr(C.kCFBooleanTrue),
		cfPtr(C.kSecMatchLimit), cfPtr(C.kSecMatchLimitOne),
		cfPtr(C.kSecUseAuthenticationUI), cfPtr(C.kSecUseAuthenticationUISkip),
	)
	defer C.CFRelease(C.CFTypeRef(query))

	var result C.CFTypeRef
	status := C.SecItemCopyMatching(query, &result)
	if status != C.errSecSuccess {
		return false, secErrString(status), nil
	}
	defer C.CFRelease(result)
	cfData := C.CFDataRef(result)
	n := int(C.CFDataGetLength(cfData))
	ptr := C.CFDataGetBytePtr(cfData)
	return true, "", C.GoBytes(unsafe.Pointer(ptr), C.int(n))
}
