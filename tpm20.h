/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef TPM20_H
#define TPM20_H

#include "types.h"
#include <tss2/tss2_sys.h>
#include <tss2/tss2_mu.h>

typedef struct TPM20 {
    void* libTcti;
    void* libTss2;
    int legacy;
    TSS2_TCTI_CONTEXT* tcti;
    TSS2_SYS_CONTEXT* context;
} TPM20;

typedef struct CertifiedKey20 {
    struct {
        int             size;
        unsigned char*  buffer;
    } publicKey;
    struct {
        int             size;
        unsigned char*  buffer;
    } privateBlob;
    struct {
        int             size;
        unsigned char*  buffer;
    } keySignature;
    struct {
        int             size;
        unsigned char*  buffer;
    } keyAttestation;
    struct {
        int             size;
        unsigned char*  buffer;
    } keyName;
} CertifiedKey20;

typedef enum TCTI {
    SOCKET_LEGACY,
    ABRMD_LEGACY,
    SOCKET,
    ABRMD,
} TCTI;

int TpmOpen20(TPM20 *tpm, TCTI tctiType);
void TpmClose20(TPM20 *tpm);
int TpmCreateCertifiedKey20(TPM20* tpm, CertifiedKey20* keyOut, Usage usage, unsigned int keyAuthSize, unsigned char keyAuth[], unsigned int parentAuthSize, const unsigned char parentAuth[]);
int TpmUnbind20(TPM20* tpm, unsigned int* unboundLenOut, unsigned char** unboundDataOut, 
    unsigned int keyAuthLen, const unsigned char* keyAuth,
    unsigned int privateKeyLen , const unsigned char* inPrivateKey, 
    unsigned int publicKeyLen, const unsigned char* inPublicKey,
    unsigned int dataLen, const unsigned char* data);
int TpmSign20(TPM20* tpm, unsigned int* signatureSizeOut, unsigned char** signatureOut, 
    const unsigned int keyAuthLen, const unsigned char* keyAuth,
    const unsigned int privateKeyLen, const unsigned char* privateKey,
    const unsigned int publicKeyLen, const unsigned char* publicKey,
    const unsigned int hashSize, const unsigned char* hash, int algId);
#endif