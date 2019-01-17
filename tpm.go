package tpm

// #cgo CFLAGS: -std=gnu11 -I${SRCDIR}/include/tss2/include -I${SRCDIR}/include/tspi/include -DMAXLOGLEVEL=LOGL_NONE
// #cgo LDFLAGS: -ldl
// #include "tpm.h"
import "C"
import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"unsafe"
)

// Tpm interface defines various methods a TPM 1.2 or TPM 2.0 chip can perform
type Tpm interface {
	Version() Version
	CreateCertifiedKey(usage Usage, keyAuth []byte, aikAuth []byte) (*CertifiedKey, error)
	Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error)
	Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hashed []byte) ([]byte, error)
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

// RSAPublicKey returns a new rsa.PublicKey from the TPM specific bits of the CertifiedKey
func (ck *CertifiedKey) RSAPublicKey() *rsa.PublicKey {
	if ck.Version == V12 {
		mod := new(big.Int)
		mod.SetBytes(ck.PublicKey)
		return &rsa.PublicKey{
			N: mod,
			E: 65537,
		}
	} else {
		mod := new(big.Int)
		start := len(ck.PublicKey) - 0x100
		end := len(ck.PublicKey)
		mod.SetBytes(ck.PublicKey[start:end])
		return &rsa.PublicKey{
			N: mod,
			E: 65537,
		}
	}
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
	if _, err := os.Stat("/sys/class/misc/tpm0/device/caps"); !os.IsNotExist(err) {
		return true
	}
	return false
}

func checkSysClassTpm20() bool {
	if _, err := os.Stat("/sys/class/tpm/tpm0/device/description"); !os.IsNotExist(err) {
		return true
	}
	tpm12Detected := checkSysClassTpm12()
	if _, err := os.Stat("/sys/class/tpm/tpm0/device"); !os.IsNotExist(err) && !tpm12Detected {
		return true
	}
	return false
}

// DetectVersion attempts to detect the installed TPM Version
func DetectVersion() Version {
	if checkSysClassTpm12() {
		return V12
	} else if checkSysClassTpm20() {
		return V20
	}
	return None
}

// Tcti is an enum that specifies what kind of TPM 2.0 TCTI to use
type Tcti int

const (
	// Legacy refers to old TPM 2.0 resourcemgr tcti
	SocketLegacy Tcti = iota
	// Abrmd refefs to TPM 2.0 modern access broker tcti
	AbrmdLegacy
	// Socket refers to TPM 2.0 modern socket tcti
	Socket
	// Abrmd refers to TPM 2.0 modern Abrmd tcti
	Abrmd
)

// Config is a global config var for specifying TPM 2.0 TCTI configurations
var Config struct {
	// Defaults to LEGACY (zero value)
	UseSimulator     bool
	SimulatorVersion Version

	V12 struct {
	}
	V20 struct {
		Tcti Tcti
	}
}

// impolicitly alled on package initialization
func init() {
	useSim, err := strconv.ParseBool(os.Getenv("FORCE_TPM_VER"))
	if err == nil {
		Config.UseSimulator = useSim
		switch simVer := os.Getenv("TPM_VER"); simVer {
		case "V12":
		case "1.2":
			Config.SimulatorVersion = V12
		case "V20":
		case "2.0":
			Config.SimulatorVersion = V20
		}
	}
	switch tcti := os.Getenv("TPM_TCTI"); tcti {
	case "socket-legacy":
		Config.V20.Tcti = SocketLegacy
	case "socket":
		Config.V20.Tcti = Socket
	case "abrmd":
		Config.V20.Tcti = Abrmd
	case "abrmd-legacy":
	default:
		Config.V20.Tcti = AbrmdLegacy
	}
}

// Open a new tpm object
func Open() (Tpm, error) {
	if Config.UseSimulator {
		switch Config.SimulatorVersion {
		case V12:
			var tpm Tpm12
			rc := C.TpmOpen12((*C.TPM12)(&tpm))
			if rc != 0 {
				return nil, errors.New(fmt.Sprintf("could not open TPM 1.2 sim: %d", rc))
			}
			return &tpm, nil
		case V20:
			var tpm Tpm20
			rc := C.TpmOpen20((*C.TPM20)(&tpm), C.TCTI(Config.V20.Tcti))
			if rc != 0 {
				return nil, errors.New(fmt.Sprintf("could not open TPM 2.0 sim: %d", rc))
			}
			return &tpm, nil
		default:
			return nil, errors.New("Config.SimulatorVersion is not set to a valid version value")
		}
	}
	switch v := DetectVersion(); v {
	case V12:
		var tpm Tpm12
		rc := C.TpmOpen12((*C.TPM12)(&tpm))
		if rc != 0 {
			return nil, errors.New(fmt.Sprintf("could not open TPM 1.2 device: %d", rc))
		}
		return &tpm, nil
	case V20:
		var tpm Tpm20
		rc := C.TpmOpen20((*C.TPM20)(&tpm), C.TCTI(Config.V20.Tcti))
		if rc != 0 {
			return nil, errors.New(fmt.Sprintf("could not open TPM 2.0 device: %d", rc))
		}
		return &tpm, nil
	default:
		return nil, errors.New("could not find TPM on the system")
	}
}

// Tpm12 is a type alias for a Native C.TPM12 structure
type Tpm12 C.TPM12

// Tpm20 is a type alias for a Native C.TPM20 structure
type Tpm20 C.TPM20

// CreateCertifiedKey creates a new signing or binding key with the specified password.
// The newly created key is then signed using the AIK which must be present on the TPM already before calling this function.
// The AIK is loaded using the provided aikAuth byte array
// A pointer to a CertifiedKey structure, which contains opaque byte blobs that represent TPM specific structures.
func (t *Tpm12) CreateCertifiedKey(usage Usage, keyAuth []byte, aikAuth []byte) (*CertifiedKey, error) {
	if t == nil {
		return nil, errors.New("invoked Tpm.CreateCertifiedKey on nil receiver")
	}
	var key C.CertifiedKey12
	defer C.free(unsafe.Pointer(key.publicKey.buffer))
	defer C.free(unsafe.Pointer(key.privateBlob.buffer))
	defer C.free(unsafe.Pointer(key.keySignature.buffer))
	defer C.free(unsafe.Pointer(key.keyAttestation.buffer))

	rc := C.TpmCreateCertifiedKey12((*C.TPM12)(t), &key, C.Usage(usage), C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])), C.uint(len(aikAuth)), (*C.uchar)(unsafe.Pointer(&aikAuth[0])))
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

// CreateCertifiedKey creates a new signing or binding key with the specified password.
// The newly created key is then signed using the AIK which must be present on the TPM already before calling this function.
// The AIK is loaded using the provided aikAuth byte array
// A pointer to a CertifiedKey structure, which contains opaque byte blobs that represent TPM specific structures.
func (t *Tpm20) CreateCertifiedKey(usage Usage, keyAuth []byte, aikAuth []byte) (*CertifiedKey, error) {
	if t == nil {
		return nil, errors.New("invoked Tpm.CreateCertifiedKey on nil receiver")
	}
	var key C.CertifiedKey20
	defer C.free(unsafe.Pointer(key.publicKey.buffer))
	defer C.free(unsafe.Pointer(key.privateBlob.buffer))
	defer C.free(unsafe.Pointer(key.keySignature.buffer))
	defer C.free(unsafe.Pointer(key.keyAttestation.buffer))
	defer C.free(unsafe.Pointer(key.keyName.buffer))

	rc := C.TpmCreateCertifiedKey20((*C.TPM20)(t), &key, C.Usage(usage), C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])), C.uint(len(aikAuth)), (*C.uchar)(unsafe.Pointer(&aikAuth[0])))
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

// Unbind decrypts data that was bound with a Binding Key created by a TPM.
// This function will load in the private key blob (which is protected and only loadable by the original TPM by its SRK)
// and then decrypt the bound data using the private key
// The CertifiedKey struct must be passed in so the Tpm can load the private blob. The binding key password must also be provided.
// Upon successful loading of the private blob, the tpm will decrypt encData, and return the plaintext
func (t *Tpm12) Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error) {
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
	rc := C.TpmUnbind12((*C.TPM12)(t), &unboundLen, &unboundData,
		C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])),
		C.uint(len(ck.PrivateKey)), (*C.uchar)(unsafe.Pointer(&ck.PrivateKey[0])),
		C.uint(len(encData)), (*C.uchar)(unsafe.Pointer(&encData[0])))
	if rc == 0 {
		return C.GoBytes(unsafe.Pointer(unboundData), C.int(unboundLen)), nil
	}
	return nil, fmt.Errorf("failed to unbind 1.2 data: %d", rc)
}

// Unbind decrypts data that was bound with a Binding Key created by a TPM.
// This function will load in the private key blob (which is protected and only loadable by the original TPM by its SRK)
// and then decrypt the bound data using the private key
// The CertifiedKey struct must be passed in so the Tpm can load the private blob. The binding key password must also be provided.
// Upon successful loading of the private blob, the tpm will decrypt encData, and return the plaintext
func (t *Tpm20) Unbind(ck *CertifiedKey, keyAuth []byte, encData []byte) ([]byte, error) {
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
	rc := C.TpmUnbind20((*C.TPM20)(t), &unboundLen, &unboundData,
		C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])),
		C.uint(len(ck.PrivateKey)), (*C.uchar)(unsafe.Pointer(&ck.PrivateKey[0])),
		C.uint(len(ck.PublicKey)), (*C.uchar)(unsafe.Pointer(&ck.PublicKey[0])),
		C.uint(len(encData)), (*C.uchar)(unsafe.Pointer(&encData[0])))
	if rc == 0 {
		return C.GoBytes(unsafe.Pointer(unboundData), C.int(unboundLen)), nil
	}
	return nil, fmt.Errorf("failed to unbind 2.0 data: %d", rc)
}

// Close finalizes a tpm object
func (t *Tpm12) Close() {
	C.TpmClose12((*C.TPM12)(t))
}

// Close finalizes a tpm object
func (t *Tpm20) Close() {
	C.TpmClose20((*C.TPM20)(t))
}

// Sign signs a blob of data using a TPM 1.2 Signing Key. A SHA384 sum of the data will be generated,
// and then signed with the private portion of the Signing Key
func (t *Tpm12) Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hash []byte) ([]byte, error) {
	if alg != crypto.SHA1 {
		return nil, errors.New("TPM 1.2 only supports SHA1")
	}
	var sigLen C.uint
	var sig *C.uchar
	defer C.free(unsafe.Pointer(sig))
	rc := C.TpmSign12((*C.TPM12)(t), &sigLen, &sig,
		C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])),
		C.uint(len(ck.PrivateKey)), (*C.uchar)(unsafe.Pointer(&ck.PrivateKey[0])),
		C.uint(len(hash)), (*C.uchar)(unsafe.Pointer(&hash[0])))
	if rc == 0 {
		return C.GoBytes(unsafe.Pointer(sig), C.int(sigLen)), nil
	}
	return nil, fmt.Errorf("failed go sign 1.2 data: %d", rc)
}

// Sign signs a blob of data using a TPM 2.0 Signing Key. A SHA384 sum of the data will be generated, and then signed with
// the private portion of the Signing Key
func (t *Tpm20) Sign(ck *CertifiedKey, keyAuth []byte, alg crypto.Hash, hash []byte) ([]byte, error) {
	var sigLen C.uint
	var sig *C.uchar
	defer C.free(unsafe.Pointer(sig))
	rc := C.TpmSign20((*C.TPM20)(t), &sigLen, &sig,
		C.uint(len(keyAuth)), (*C.uchar)(unsafe.Pointer(&keyAuth[0])),
		C.uint(len(ck.PrivateKey)), (*C.uchar)(unsafe.Pointer(&ck.PrivateKey[0])),
		C.uint(len(ck.PublicKey)), (*C.uchar)(unsafe.Pointer(&ck.PublicKey[0])),
		C.uint(len(hash)), (*C.uchar)(unsafe.Pointer(&hash[0])),
		C.int(alg))
	if rc == 0 {
		return C.GoBytes(unsafe.Pointer(sig), C.int(sigLen)), nil
	}
	return nil, fmt.Errorf("failed to sign 2.0 data: %d", rc)
}

// Version returns V12
func (t *Tpm12) Version() Version {
	return V12
}

// Version return V20
func (t *Tpm20) Version() Version {
	return V20
}
