#ifndef TPM12_H
#define TPM12_H

#include "types.h"
#include <trousers/tss.h>
#include <trousers/trousers.h>

typedef struct TPM12 {
    TSS_HCONTEXT context;
    TSS_HTPM     device;
    TSS_HPOLICY  policy;
} TPM12;

typedef struct CertifiedKey12 {
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
} CertifiedKey12;

int TpmOpen12(TPM12* tpm);
void TpmClose12(TPM12* tpm);
int TpmCreateCertifiedKey12(TPM12* tpm, CertifiedKey12* keyOut, Usage usage, unsigned int keyAuthSize, const unsigned char keyAuth[], unsigned int parentAuthSize, const unsigned char parentAuth[]);
int TpmUnbind12(TPM12* tpm, unsigned int* unboundLenOut, unsigned char** unboundDataOut,
 unsigned int keyAuthLen, const unsigned char* keyAuth,
 unsigned int privateKeyLen , const unsigned char* inKey, 
  unsigned int dataLen, const unsigned char* data);
int TpmSign12(TPM12* tpm, unsigned int* signatureSizeOut, unsigned char** signatureOut,
 const unsigned int keyAuthLen, const unsigned char* keyAuth, 
 const unsigned int privateKeyLen, const unsigned char* privateKey,
 const unsigned int dataSize, const unsigned char* data);
#endif