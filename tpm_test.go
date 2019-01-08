package tpm

import "testing"
import "github.com/stretchr/testify/assert"

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
