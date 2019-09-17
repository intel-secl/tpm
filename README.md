# ISecL TPM Library

This library provides several tpm functions for TPM 2.0 chip.

Currently, only two functions are provided: 
 - CreateCertifiedKey() creates a new binding or signing key that is signed by a parent key (usually an aik)
 - Unbind() decrypts data that was bound using a binding key (created by the above CreateCertifiedKey)
 
A simple command line runner that invokes library functions is included. Currently, only key creation is supported by the command line runner.

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- Go 11.4 or newer

# Step By Step Build Instructions

## Install required shell commands

### Install `go 1.11.4` or newer
The `tpm` library requires Go version 11.4 that has support for `go modules`. The build was validated with version 11.4 version of `go`. It is recommended that you use a newer version of `go` - but please keep in mind that the product has been validated with 1.11.4 and newer versions of `go` may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.11.4.linux-amd64.tar.gz
tar -xzf go1.11.4.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build tpm

- Git clone the tpm
- Run scripts to build the tpm

```shell
git clone https://github.com/intel-secl/tpm.git
cd tpm
go build ./...
```

# Links
https://01.org/intel-secl/
