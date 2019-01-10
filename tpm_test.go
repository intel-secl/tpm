package tpm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTpm12(t *testing.T) {
	Config.UseSimulator = true
	Config.SimulatorVersion = V12

	tpm, err := Open()
	assert.NoError(t, err)
	if err == nil {
		defer tpm.Close()
		bk, err := tpm.CreateCertifiedKey(Binding, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(t, err)
		if err != nil {
			return
		}
		assert.NotEmpty(t, bk.PublicKey)
		assert.NotEmpty(t, bk.PrivateKey)
		assert.NotEmpty(t, bk.KeySignature)
		assert.NotEmpty(t, bk.KeyAttestation)
		assert.Empty(t, bk.KeyName)
		assert.Equal(t, bk.Usage, Binding)
		assert.Equal(t, bk.Version, V12)

		// test unbind
		pub := bk.RSAPublicKey()
		rng := rand.Reader
		message := []byte{
			1, 1, 1, 1, // version
			2, // TPM_PT_BIND
			'f', 'o', 'o', 'b', 'a', 'r',
		}
		cipher, err := rsa.EncryptOAEP(sha1.New(), rng, pub, message, []byte{'T', 'C', 'P', 'A'})
		assert.NoError(t, err)
		dec, err := tpm.Unbind(bk, []byte{'1', '2', '3', '4'}, cipher)
		assert.NoError(t, err)
		assert.Equal(t, []byte{'f', 'o', 'o', 'b', 'a', 'r'}, dec)

		sk, err := tpm.CreateCertifiedKey(Signing, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(t, err)
		if err != nil {
			return
		}
		assert.NotEmpty(t, sk.PublicKey)
		assert.NotEmpty(t, sk.PrivateKey)
		assert.NotEmpty(t, sk.KeySignature)
		assert.NotEmpty(t, sk.KeyAttestation)
		assert.Empty(t, sk.KeyName)
		assert.Equal(t, sk.Usage, Signing)
		assert.Equal(t, sk.Version, V12)
	}
}

func TestTpm20Legacy(t *testing.T) {
	Config.UseSimulator = true
	Config.SimulatorVersion = V20
	Config.V20.Tcti = SocketLegacy

	tpm, err := Open()
	assert.NoError(t, err)
	if err == nil {
		defer tpm.Close()
		bk, err := tpm.CreateCertifiedKey(Binding, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(t, err)
		if err != nil {
			return
		}
		assert.NotEmpty(t, bk.PublicKey)
		assert.NotEmpty(t, bk.PrivateKey)
		assert.NotEmpty(t, bk.KeySignature)
		assert.NotEmpty(t, bk.KeyAttestation)
		assert.NotEmpty(t, bk.KeyName)
		assert.Equal(t, bk.Usage, Binding)
		assert.Equal(t, bk.Version, V20)

		// test unbind
		pub := bk.RSAPublicKey()
		rng := rand.Reader
		message := []byte("foobar")
		cipher, err := rsa.EncryptOAEP(sha256.New(), rng, pub, message, []byte{'T', 'C', 'P', 'A'})
		assert.NoError(t, err)
		dec, err := tpm.Unbind(bk, []byte{'1', '2', '3', '4'}, cipher)
		assert.NoError(t, err)
		assert.Equal(t, message, dec)

		sk, err := tpm.CreateCertifiedKey(Signing, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(t, err)
		if err != nil {
			return
		}
		assert.NotEmpty(t, sk.PublicKey)
		assert.NotEmpty(t, sk.PrivateKey)
		assert.NotEmpty(t, sk.KeySignature)
		assert.NotEmpty(t, sk.KeyAttestation)
		assert.NotEmpty(t, sk.KeyName)
		assert.Equal(t, sk.Usage, Signing)
		assert.Equal(t, sk.Version, V20)
	}
}
func TestTpm20(t *testing.T) {
	Config.UseSimulator = true
	Config.SimulatorVersion = V20
	Config.V20.Tcti = Socket

	tpm, err := Open()
	assert := assert.New(t)
	assert.NoError(err)
	if err == nil {
		defer tpm.Close()
		bk, err := tpm.CreateCertifiedKey(Binding, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(err)
		if err != nil {
			return
		}
		assert.NotEmpty(bk.PublicKey)
		assert.NotEmpty(bk.PrivateKey)
		assert.NotEmpty(bk.KeySignature)
		assert.NotEmpty(bk.KeyAttestation)
		assert.NotEmpty(bk.KeyName)
		assert.Equal(bk.Usage, Binding)
		assert.Equal(bk.Version, V20)

		// test unbind
		pub := bk.RSAPublicKey()
		rng := rand.Reader
		message := []byte("foobar")
		cipher, err := rsa.EncryptOAEP(sha256.New(), rng, pub, message, []byte{'T', 'C', 'P', 'A'})
		assert.NoError(err)
		dec, err := tpm.Unbind(bk, []byte{'1', '2', '3', '4'}, cipher)
		assert.NoError(err)
		assert.Equal(message, dec)
		sk, err := tpm.CreateCertifiedKey(Signing, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(err)
		if err != nil {
			return
		}
		assert.NotEmpty(sk.PublicKey)
		assert.NotEmpty(sk.PrivateKey)
		assert.NotEmpty(sk.KeySignature)
		assert.NotEmpty(sk.KeyAttestation)
		assert.NotEmpty(sk.KeyName)
		assert.Equal(sk.Usage, Signing)
		assert.Equal(sk.Version, V20)
	}
}
