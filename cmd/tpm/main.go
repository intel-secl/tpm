package main

import (
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"intel/isecl/lib/tpm"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func fileExists(keyFilePath string) bool {
	// check if key file exists
	_, err := os.Stat(keyFilePath)
	if os.IsNotExist(err) {
		return false
	}
	return true

}
func getFileContents(keyFilePath string) []byte {

	// read contents of file
	file, _ := os.Open(keyFilePath)
	defer file.Close()
	byteValue, _ := ioutil.ReadAll(file)
	return byteValue
}

func getBytesFromBase64(data string) (ret []byte) {

	ret, _ = base64.StdEncoding.DecodeString(data)
	return
}

func getBase64FromBytes(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// GetHash returns a byte array to the hash of the data.
// alg indicates the hashing algorithm. Currently, the only supported hashing algorithms
// are SHA1, SHA256, SHA384 and SHA512
func getHashData(data []byte, alg crypto.Hash) []byte {

	switch alg {
	case crypto.SHA1:
		s := sha1.Sum(data)
		return s[:]
	case crypto.SHA256:
		s := sha256.Sum256(data)
		return s[:]
	case crypto.SHA384:
		//SHA384 is implemented in the sha512 package
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}

	return nil
}

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

func sign() {

	args := os.Args[2:]
	if len(args) != 3 {
		printUsage()
		return
	}

	if !fileExists(args[0]) {
		fmt.Println("Error: File Does not exist FileName:", args[0])
	}

	fmt.Println("Secret (base64):", args[1])
	fmt.Println("Secret (byteArray):", getBytesFromBase64(args[1]))

	var ck tpm.CertifiedKey
	err := json.Unmarshal(getFileContents(args[0]), &ck)
	if err != nil {
		fmt.Println("Error: Could not unmarshal data Error: ", err)
		fmt.Println("FileName :", args[0])
		return
	}

	fmt.Println("Original Data:", args[2])
	fmt.Println("Sha384:", getHashData([]byte(args[2]), crypto.SHA384))
	fmt.Println("Certified Key String")
	jsondat, _ := json.Marshal(ck)
	fmt.Println(string(jsondat))

	t, err := tpm.Open()
	if err != nil {
		log.Fatal(err)
	}
	defer t.Close()

	signature, err := t.Sign(&ck, getBytesFromBase64(args[1]), crypto.SHA384, getHashData([]byte(args[2]), crypto.SHA384))
	if err != nil {
		fmt.Println("Error", err)
		return
	}
	fmt.Println("Success")
	fmt.Println(signature)

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
	fmt.Println("Sign <SigningCertifiedKeyPath> <Base64SigningSecret> <data>")
	fmt.Println("\tOriginal Data: ")
	fmt.Println("\tSha384 Hash(in base64): ")
	fmt.Println("\tSignature(in base64):")

}

func main() {
	args := os.Args[1:]
	if len(args) <= 0 {
		printUsage()
		return
	}

	switch arg := args[0]; strings.ToLower(arg) {
	case "createcertifiedkey":
		createCertifiedKey()
	case "unbind":
		unbind()
	case "sign":
		sign()
	default:
		fmt.Printf("Unrecognized option %s\n", arg)
		printUsage()
	}
}
