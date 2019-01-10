package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"intel/isecl/lib/tpm"
)

func createCertifiedKey() {
	args := os.Args[2:]
	if len(args) != 3 {
		printUsage()
		return
	}

	var usage tpm.Usage
	if os.Args[2] == "bind" {
		usage = tpm.Binding
	} else if os.Args[2] == "sign" {
		usage = tpm.Signing
	} else {
		printUsage()
		return
	}

	keyAuth, err := hex.DecodeString(os.Args[3])
	if err != nil {
		printUsage()
		return
	}

	aikAuth, err := hex.DecodeString(os.Args[4])
	if err != nil {
		printUsage()
		return
	}

	t, err := tpm.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer t.Close()
	ck, err := t.CreateCertifiedKey(usage, keyAuth, aikAuth)
	if err != nil {
		fmt.Println("CreateCertifiedKey failed with error:", err)
		return
	}
	fmt.Println("Key TPM Version:", ck.Version)
	fmt.Println("Private Key:\n", hex.EncodeToString(ck.PrivateKey))
	fmt.Println("Public Key:\n", hex.EncodeToString(ck.PublicKey))
	fmt.Println("KeySignature:\n", hex.EncodeToString(ck.KeySignature))
	fmt.Println("KeyAttestation:\n", hex.EncodeToString(ck.KeyAttestation))
	if len(ck.KeyAttestation) > 0 {
		fmt.Println("KeyName:\n", hex.EncodeToString(ck.KeyName))
	}
}

func unbind() {
	args := os.Args[2:]
	if len(args) != 4 {
		printUsage()
		return
	}

	t, err := tpm.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer t.Close()
	keyAuth, err := hex.DecodeString(args[0])
	if err != nil {
		log.Fatal(err)
	}
	pub, err := hex.DecodeString(args[1])
	if err != nil {
		log.Fatal(err)
	}
	prv, err := hex.DecodeString(args[2])
	if err != nil {
		log.Fatal(err)
	}
	encData, err := hex.DecodeString(args[3])
	if err != nil {
		log.Fatal(err)
	}
	var ver tpm.Version
	_, ok := t.(*tpm.Tpm20)
	if ok {
		ver = tpm.V20
	} else {
		ver = tpm.V12
	}
	ck := tpm.CertifiedKey{
		Version:    ver,
		PublicKey:  pub,
		PrivateKey: prv,
	}
	data, err := t.Unbind(&ck, keyAuth, encData)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Plain text:\n", hex.EncodeToString(data))
}

func printUsage() {
	fmt.Println(os.Args[0], "[options]")
	fmt.Println("CreateCertifiedKey <usage := bind|sign> <keyAuth := hexstring> <aikAuth := hexstring>")
	fmt.Println("\tOutput: <publicKey, privateKey, keySignature, keyAttestation, keyName:optional>")
	fmt.Println("Unbind <keyAuth> <publicKey> <privateKey> <encrypteddata>")
	fmt.Println("\tOutput: <decrypteddata>")
}

func main() {
	args := os.Args[1:]
	if len(args) <= 0 {
		printUsage()
		return
	}

	switch arg := args[0]; arg {
	case "CreateCertifiedKey":
		createCertifiedKey()
	case "Unbind":
		unbind()
	default:
		fmt.Printf("Unrecognized option %s\n", arg)
		printUsage()
	}
}
