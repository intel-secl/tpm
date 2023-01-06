DISCONTINUATION OF PROJECT

This project will no longer be maintained by Intel.

Intel has ceased development and contributions including, but not limited to, maintenance, bug fixes, new releases, or updates, to this project.  

Intel no longer accepts patches to this project.

If you have an ongoing need to use this project, are interested in independently developing it, or would like to maintain patches for the open source software community, please create your own fork of this project.  
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
- `go` version >= `go1.12.12` & <= `go1.12.17`

# Step By Step Build Instructions

## Install required shell commands

### Install `go` version >= `go1.12.12` & <= `go1.12.17`
The `tpm` library requires Go version 1.12.12 that has support for `go modules`. The build was validated with the latest version 1.12.17 of `go`. It is recommended that you use 1.12.17 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.12.17.linux-amd64.tar.gz
tar -xzf go1.12.17.linux-amd64.tar.gz
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
