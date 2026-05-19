// Package ope provides Go bindings for Open Privacy Envelope (OPE) via libope_ffi.
package ope

/*
#cgo CFLAGS: -I${SRCDIR}/../../c/include
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lope_ffi -Wl,-rpath,${SRCDIR}/../../../target/release -Wl,-rpath,${SRCDIR}/../../../target/debug
#cgo linux LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lope_ffi -Wl,-rpath,${SRCDIR}/../../../target/release -Wl,-rpath,${SRCDIR}/../../../target/debug
#include "ope.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"
)

const KeySize = 32

var (
	ErrVerify = errors.New("ope: verification failed")
)

// Version returns the linked ope-ffi version string.
func Version() string {
	return C.GoString(C.ope_version())
}

// LastError returns the last error message from the native library.
func LastError() string {
	buf := make([]byte, 512)
	C.ope_last_error_message((*C.char)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)))
	return string(buf)
}

func check(rc C.int, op string) error {
	if rc == C.OPE_OK {
		return nil
	}
	return fmt.Errorf("%s: %s (code %d)", op, LastError(), int(rc))
}

// EnvelopeSign signs an envelope JSON object and returns the signed JSON string.
func EnvelopeSign(secretKey [KeySize]byte, envelopeJSON []byte) (string, error) {
	var out *C.char
	rc := C.ope_envelope_sign(
		(*C.uint8_t)(unsafe.Pointer(&secretKey[0])),
		(*C.char)(unsafe.Pointer(&envelopeJSON[0])),
		&out,
	)
	if err := check(rc, "ope_envelope_sign"); err != nil {
		return "", err
	}
	defer C.ope_string_free(out)
	return C.GoString(out), nil
}

// EnvelopeSignMap signs a map (serialized to JSON).
func EnvelopeSignMap(secretKey [KeySize]byte, envelope map[string]any) (string, error) {
	raw, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return EnvelopeSign(secretKey, raw)
}

// EnvelopeVerify verifies an envelope JSON string with the given public key.
func EnvelopeVerify(publicKey [KeySize]byte, envelopeJSON []byte, maxSkewSecs uint32) error {
	rc := C.ope_envelope_verify(
		(*C.uint8_t)(unsafe.Pointer(&publicKey[0])),
		(*C.char)(unsafe.Pointer(&envelopeJSON[0])),
		C.uint32_t(maxSkewSecs),
	)
	if rc == C.OPE_ERR_VERIFY {
		return fmt.Errorf("%w: %s", ErrVerify, LastError())
	}
	return check(rc, "ope_envelope_verify")
}

// EnvelopeVerifyDev verifies using the dev vector-001 mock key (development only).
func EnvelopeVerifyDev(envelopeJSON []byte) error {
	rc := C.ope_envelope_verify_dev_json((*C.char)(unsafe.Pointer(&envelopeJSON[0])))
	if rc == C.OPE_ERR_VERIFY {
		return fmt.Errorf("%w: %s", ErrVerify, LastError())
	}
	return check(rc, "ope_envelope_verify_dev_json")
}

// DefaultLibPath returns the expected libope_ffi path under the repo target/ dir.
func DefaultLibPath(repoRoot string) string {
	var name string
	switch runtime.GOOS {
	case "darwin":
		name = "libope_ffi.dylib"
	case "linux":
		name = "libope_ffi.so"
	default:
		name = "ope_ffi.dll"
	}
	release := filepath.Join(repoRoot, "target", "release", name)
	if _, err := os.Stat(release); err == nil {
		return release
	}
	return filepath.Join(repoRoot, "target", "debug", name)
}
