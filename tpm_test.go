// +build integration

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

		// Test many keys
		for i := 0; i < 3; i++ {
			_, err := tpm.CreateCertifiedKey(Binding, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
			assert.NoError(t, err)
		}

		// test unbind
		pub := bk.RSAPublicKey()
		rng := rand.Reader
		message := []byte("foobar")
		cipher, err := rsa.EncryptOAEP(sha256.New(), rng, pub, message, []byte{'T', 'P', 'M', '2', 0})
		assert.NoError(t, err)
		dec, err := tpm.Unbind(bk, []byte{'1', '2', '3', '4'}, cipher)
		assert.NoError(t, err)
		assert.Equal(t, message, dec)

		sk, err := tpm.CreateCertifiedKey(Signing, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(t, err)
		if err != nil {
			return
		}

		// test sign
		signMessage := []byte("foobar")
		hashed := sha512.Sum384(signMessage)
		sig, err := tpm.Sign(sk, []byte{'1', '2', '3', '4'}, crypto.SHA384, hashed[:])
		assert.NoError(t, err)

		// validate that the sig matches

		pub = sk.RSAPublicKey()
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA384, hashed[:], sig)
		assert.NoError(t, err)

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

		// Test many keys
		for i := 0; i < 3; i++ {
			_, err := tpm.CreateCertifiedKey(Binding, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
			assert.NoError(err)
		}

		// test unbind
		pub := bk.RSAPublicKey()
		rng := rand.Reader
		message := []byte("foobar")
		cipher, err := rsa.EncryptOAEP(sha256.New(), rng, pub, message, []byte{'T', 'P', 'M', '2', 0})
		assert.NoError(err)
		dec, err := tpm.Unbind(bk, []byte{'1', '2', '3', '4'}, cipher)
		assert.NoError(err)
		assert.Equal(message, dec)

		sk, err := tpm.CreateCertifiedKey(Signing, []byte{'1', '2', '3', '4'}, []byte{'5', '6', '7', '8'})
		assert.NoError(err)
		if err != nil {
			return
		}

		// test sign
		signMessage := []byte("foobar")
		hashed := sha512.Sum384(signMessage)
		sig, err := tpm.Sign(sk, []byte{'1', '2', '3', '4'}, crypto.SHA384, hashed[:])
		assert.NoError(err)

		// validate that the sig matches
		pub = sk.RSAPublicKey()
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA384, hashed[:], sig)
		assert.NoError(err)
		assert.NotEmpty(sk.PublicKey)
		assert.NotEmpty(sk.PrivateKey)
		assert.NotEmpty(sk.KeySignature)
		assert.NotEmpty(sk.KeyAttestation)
		assert.NotEmpty(sk.KeyName)
		assert.Equal(sk.Usage, Signing)
		assert.Equal(sk.Version, V20)
	}
}
