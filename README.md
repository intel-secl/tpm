# ISecL TPM Library

This library provides several tpm functions for TPM 2.0 chip.

Currently, only two functions are provided: 
 - CreateCertifiedKey() creates a new binding or signing key that is signed by a parent key (usually an aik)
 - Unbind() decrypts data that was bound using a binding key (created by the above CreateCertifiedKey)
 
A simple command line runner that invokes library functions is included. Currently, only key creation is supported by the command line runner.
