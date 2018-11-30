package tpm

// #cgo CFLAGS: -I${SRCDIR}/include/tss2/include -I${SRCDIR}/include/tspi/include
// #cgo LDFLAGS: -ldl
// #include "tpm.h"
import "C"
import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"unsafe"
)

// Tpm interface
type Tpm interface {
	// CreateCertifiedKey creates a new binding or signing key that is certified by the AIK
	CreateCertifiedKey(usage Usage, keyAuth []byte, aikAuth []byte) (*CertifiedKey, error)
	Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error)
	Close()
}

// CertifiedKey contains TPM 1.2 or 2.0 key data and signature
type CertifiedKey struct {
	Version        Version
	Usage          Usage
	PublicKey      []byte
	PrivateKey     []byte
	KeySignature   []byte
	KeyAttestation []byte
	// KeyName may be nil if the key comes from a TPM 1.2 chip
	KeyName []byte
}

// Version enumerates the detected TPM Version. Can be NONE, V12, or V20
type Version int

const (
	// None means no TPM found
	None Version = iota
	// V12 means TPM 1.2
	V12
	// V20 means TPM 2.0
	V20
)

// Usage indicates how a key should be used. Can be either BINDING or SIGNING
type Usage int

const (
	// Binding a tpm key meant only for binding operations
	Binding Usage = iota
	// Signing a tpm key meant only for signing operations
	Signing
)

func checkSysClassTpm12() bool {
	if _, err := os.Stat("/sys/class/tpm/tpm0/device/caps"); !os.IsNotExist(err) {
		return true
	}
	return false
}

func checkSysClassTpm20() bool {
	if _, err := os.Stat("/sys/class/tpm/tpm0/device/description"); !os.IsNotExist(err) {
		return true
	}
	return false
}

// DetectVersion attempts to detect the installed TPM Version
func DetectVersion() Version {
	if checkSysClassTpm20() {
		return V20
	} else if checkSysClassTpm12() {
		return V12
	}
	return None
}

// Tcti is an enum that specifies what kind of TPM 2.0 TCTI to use
type Tcti int

const (
	// Legacy refers to old TPM 2.0 resourcemgr tcti
	Legacy Tcti = iota
	// Abrmd refefs to TPM 2.0 modern access broker tcti
	Abrmd
	// Socket refers to TPM 2.0 modern socket tcti
	Socket
)

// Config is a global config var for specifying TPM 2.0 TCTI configurations
var Config struct {
	// Defaults to LEGACY (zero value)
	UseSimulator     bool
	SimulatorVersion Version
	Tcti             Tcti
}

// impolicitly alled on package initialization
func init() {
	useSim, err := strconv.ParseBool(os.Getenv("USE_TPM_SIM"))
	if err == nil {
		Config.UseSimulator = useSim
		switch simVer := os.Getenv("TPM_SIM_VER"); simVer {
		case "V12":
		case "1.2":
			Config.SimulatorVersion = V12
		case "V20":
		case "2.0":
			Config.SimulatorVersion = V20
		}
	}
}

// Open a new tpm object
func Open() (Tpm, error) {
	if Config.UseSimulator {
		switch Config.SimulatorVersion {
		case V12:
			var tpm C.TPM12
			C.TpmOpen12(&tpm)
			return &tpm, nil
		case V20:
			var tpm C.TPM20
			C.TpmOpen20(&tpm, C.TCTI(Socket))
			return &tpm, nil
		default:
			return nil, errors.New("Config.SimulatorVersion is not set to a valid verison value")
		}
	}
	switch v := DetectVersion(); v {
	case V12:
		var tpm C.TPM12
		C.TpmOpen12(&tpm)
		return &tpm, nil
	case V20:
		var tpm C.TPM20
		C.TpmOpen20(&tpm, C.TCTI(Config.Tcti))
		return &tpm, nil
	default:
		return nil, errors.New("could not find TPM on the system")
	}
}

func (t *C.TPM12) CreateCertifiedKey(usage Usage, keyAuth []byte, aikAuth []byte) (*CertifiedKey, error) {
	if t == nil {
		return nil, errors.New("invoked Tpm.CreateCertifiedKey on nil receiver")
	}
	var key C.CertifiedKey12
	defer C.free(unsafe.Pointer(key.publicKey.buffer))
	defer C.free(unsafe.Pointer(key.privateBlob.buffer))
	defer C.free(unsafe.Pointer(key.keySignature.buffer))
	defer C.free(unsafe.Pointer(key.keyAttestation.buffer))

	rc := C.TpmCreateCertifiedKey12(t, &key, C.Usage(usage), C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])), C.uint(len(aikAuth)), (*C.uchar)(unsafe.Pointer(&aikAuth[0])))
	if rc == 0 {
		return &CertifiedKey{
			Version:        V12,
			Usage:          usage,
			PublicKey:      C.GoBytes(unsafe.Pointer(key.publicKey.buffer), key.publicKey.size),
			PrivateKey:     C.GoBytes(unsafe.Pointer(key.privateBlob.buffer), key.privateBlob.size),
			KeySignature:   C.GoBytes(unsafe.Pointer(key.keySignature.buffer), key.keySignature.size),
			KeyAttestation: C.GoBytes(unsafe.Pointer(key.keyAttestation.buffer), key.keyAttestation.size),
			KeyName:        nil,
		}, nil
	}
	return nil, fmt.Errorf("failed to create tpm 1.2 key: %d", int(rc))
}

func (t *C.TPM20) CreateCertifiedKey(usage Usage, keyAuth []byte, aikAuth []byte) (*CertifiedKey, error) {
	if t == nil {
		return nil, errors.New("invoked Tpm.CreateCertifiedKey on nil receiver")
	}
	var key C.CertifiedKey20
	defer C.free(unsafe.Pointer(key.publicKey.buffer))
	defer C.free(unsafe.Pointer(key.privateBlob.buffer))
	defer C.free(unsafe.Pointer(key.keySignature.buffer))
	defer C.free(unsafe.Pointer(key.keyAttestation.buffer))
	defer C.free(unsafe.Pointer(key.keyName.buffer))

	rc := C.TpmCreateCertifiedKey20(t, &key, C.Usage(usage), C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])), C.uint(len(aikAuth)), (*C.uchar)(unsafe.Pointer(&aikAuth[0])))
	if rc == 0 {
		return &CertifiedKey{
			Version:        V20,
			Usage:          usage,
			PublicKey:      C.GoBytes(unsafe.Pointer(key.publicKey.buffer), key.publicKey.size),
			PrivateKey:     C.GoBytes(unsafe.Pointer(key.privateBlob.buffer), key.privateBlob.size),
			KeySignature:   C.GoBytes(unsafe.Pointer(key.keySignature.buffer), key.keySignature.size),
			KeyAttestation: C.GoBytes(unsafe.Pointer(key.keyAttestation.buffer), key.keyAttestation.size),
			KeyName:        C.GoBytes(unsafe.Pointer(key.keyName.buffer), key.keyName.size),
		}, nil
	}
	return nil, fmt.Errorf("failed to create 2.0 key: %d", rc)
}

func (t *C.TPM12) Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error) {
	// int TpmUnbind12(TPM12* tpm, unsigned int* unboundLenOut, unsigned char** unboundDataOut,
	// 					unsigned int privateKeyLen , const unsigned char* inKey,
	//					unsigned int keyAuthLen, const unsigned char* keyAuth,
	//					unsigned int dataLen, const unsigned char* data);
	if t == nil {
		return nil, errors.New("invoked Tpm.Unbind on nil receiver")
	}
	var unboundLen C.uint
	var unboundData *C.uchar
	defer C.free(unsafe.Pointer(unboundData))
	rc := C.TpmUnbind12(t, &unboundLen, &unboundData,
		C.uint(len(ck.PrivateKey)), (*C.uchar)(unsafe.Pointer(&ck.PrivateKey[0])),
		C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])),
		C.uint(len(encData)), (*C.uchar)(unsafe.Pointer(&encData[0])))
	if rc == 0 {
		return C.GoBytes(unsafe.Pointer(unboundData), C.int(unboundLen)), nil
	}
	return nil, fmt.Errorf("failed to unbind 1.2 data: %d", rc)
}

func (t *C.TPM20) Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error) {
	//int TpmUnbind20(TPM20* tpm, unsigned int* unboundLenOut, unsigned char** unboundDataOut,
	//					unsigned int privateKeyLen , const unsigned char* inPrivateKey,
	//					unsigned int publicKeyLen, const unsigned char* inPublicKey,
	//					unsigned int keyAuthLen, const unsigned char* keyAuth,
	//					unsigned int dataLen, const unsigned char* data);
	if t == nil {
		return nil, errors.New("invoked Tpm.Unbind on nil receiver")
	}
	var unboundLen C.uint
	var unboundData *C.uchar
	defer C.free(unsafe.Pointer(unboundData))
	rc := C.TpmUnbind20(t, &unboundLen, &unboundData,
		C.uint(len(ck.PrivateKey)), (*C.uchar)(unsafe.Pointer(&ck.PrivateKey[0])),
		C.uint(len(ck.PublicKey)), (*C.uchar)(unsafe.Pointer(&ck.PublicKey[0])),
		C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])),
		C.uint(len(encData)), (*C.uchar)(unsafe.Pointer(&encData[0])))
	if rc == 0 {
		return C.GoBytes(unsafe.Pointer(unboundData), C.int(unboundLen)), nil
	}
	return nil, fmt.Errorf("failed to unbind 2.0 data: %d", rc)
}

func (t *C.TPM12) Close() {
	C.TpmClose12(t)
}

func (t *C.TPM20) Close() {
	C.TpmClose20(t)
}
