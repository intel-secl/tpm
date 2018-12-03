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
	fmt.Println("Private Key:", hex.EncodeToString(ck.PrivateKey))
	fmt.Println("Public Key:", hex.EncodeToString(ck.PublicKey))
	fmt.Println("KeySignature:", hex.EncodeToString(ck.KeySignature))
	fmt.Println("KeyAttestation:", hex.EncodeToString(ck.KeyAttestation))
}

func unbind() {
	fmt.Println("Not yet supported")
}

func printUsage() {
	fmt.Println(os.Args[0], "[options]")
	fmt.Println("CreateCertifiedKey <usage := bind|sign> <keyAuth := hexstring> <aikAuth := hexstring>")
	fmt.Println("\tOutput: <publicKey, privateKey, keySignature, keyAttestation>")
	fmt.Println("Unbind <privateKey> <encrypteddata>")
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
