/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm12.h"
#include <string.h>
#include <stdio.h>

#define CHECK(rc) if ((rc) != TSS_SUCCESS) { fprintf(stderr, "Failure at: %s:%d\n", __FILE__, __LINE__); goto out; }

TSS_RESULT loadSrk(TPM12* tpm, TSS_HKEY* srk, TSS_HPOLICY* srkPolicy) {
    TSS_RESULT rc;
    TSS_UUID srkUuid = TSS_UUID_SRK;
    const TSS_HCONTEXT context = tpm->context;
    BYTE wks[] = TSS_WELL_KNOWN_SECRET;
    CHECK(rc = Tspi_Context_CreateObject(context, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TSP_SRK, srk));
    CHECK(rc = Tspi_Context_LoadKeyByUUID(context, TSS_PS_TYPE_SYSTEM, srkUuid, srk));
    CHECK(rc = Tspi_Context_CreateObject(context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, srkPolicy));
    CHECK(rc = Tspi_Policy_SetSecret(*srkPolicy, TSS_SECRET_MODE_PLAIN, sizeof(wks), wks));
    CHECK(rc = Tspi_Policy_AssignToObject(*srkPolicy, *srk));
out:
    return rc;
}

int TpmOpen12(TPM12* tpm) {
    TSS_RESULT rc;

    if (tpm == NULL) {
        return -1;
    }
    tpm->context = 0;
    tpm->device = 0;

    rc = Tspi_Context_Create(&tpm->context);
    rc = Tspi_Context_Connect(tpm->context, NULL);
    rc = Tspi_Context_GetTpmObject(tpm->context, &tpm->device);
    rc = Tspi_Context_GetDefaultPolicy(tpm->context, &tpm->policy);
    return (int)rc;
}

void TpmClose12(TPM12* tpm) {
    if (tpm != NULL) {
        if (tpm->context) {
            Tspi_Context_Close(tpm->context);
            tpm->context = 0;
        }
        tpm->device = 0;
    }
}
    
int TpmCreateCertifiedKey12(TPM12* tpm, CertifiedKey12* keyOut, Usage usage, unsigned int keyAuthSize, const unsigned char* keyAuth, unsigned int parentAuthSize, const unsigned char* parentAuth) {
    TSS_HKEY    srk = 0, 
                aik = 0, 
                key = 0;
    TSS_HPOLICY policy_aik = 0, 
                policy_srk = 0, 
                policy_key = 0;
    TSS_UUID    uuid_srk = TSS_UUID_SRK,
                uuid_aik = TSS_UUID_USK2,
                uuid_key = TSS_UUID_USK2;

    UINT32      mod_size = 0,
                blob_size = 0;
    BYTE        *mod_blob = NULL,
                *blob_blob = NULL,
                *randomData = NULL;
    TSS_VALIDATION  pValidationData = {};
    TSS_RESULT rc = 0;

    uuid_key.rgbNode[5] = usage == BINDING ? 3 : 4;
    uuid_aik.rgbNode[5] = 1;
    uuid_aik.rgbNode[0] = 0x04;
    // Check parameters
    if (tpm == NULL) {
        return -1;
    }
    if (usage != BINDING && usage != SIGNING) {
        return -2;
    }
    if (keyAuth == NULL) {
        return -3;
    }
    if (parentAuth == NULL) {
        return -4;
    }

    // Load SRK
    CHECK(rc = loadSrk(tpm, &srk, &policy_srk));

    // Load AIk
    CHECK(rc = Tspi_Context_GetKeyByUUID(tpm->context, TSS_PS_TYPE_SYSTEM, uuid_aik, &aik));
    CHECK(rc = Tspi_Key_LoadKey(aik, srk));
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policy_aik));
    CHECK(rc = Tspi_Policy_SetSecret(policy_aik, TSS_SECRET_MODE_PLAIN, parentAuthSize, (BYTE*)parentAuth));
    CHECK(rc = Tspi_Policy_AssignToObject(policy_aik, aik));
    
    TSS_FLAG init_flags;
    if (usage == BINDING) {
        uuid_key.rgbNode[0] = 0x05;
        init_flags = TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048 | TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
    } else if (usage == SIGNING) {
        uuid_key.rgbNode[0] = 0x6;
        init_flags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048 | TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
    } else {
        rc = -5;
        goto out;
    }

    // Create New Key
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_RSAKEY, init_flags, &key));
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policy_key));
    CHECK(rc = Tspi_Policy_SetSecret(policy_key, TSS_SECRET_MODE_PLAIN, keyAuthSize, (BYTE*)keyAuth));
    CHECK(rc = Tspi_Policy_AssignToObject(policy_key, key));
    CHECK(rc = Tspi_Key_CreateKey(key, srk, (TSS_HPCRS)0));

    CHECK(rc = Tspi_GetAttribData(key, TSS_TSPATTRIB_RSAKEY_INFO, TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &mod_size, &mod_blob));
    CHECK(rc = Tspi_GetAttribData(key, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB, &blob_size, &blob_blob));

    CHECK(rc = Tspi_Key_LoadKey(key, srk));
    CHECK(rc = Tspi_TPM_GetRandom(tpm->device, 20, &randomData));

    pValidationData.ulExternalDataLength = 20;
    pValidationData.rgbExternalData = randomData;
    CHECK(rc = Tspi_Key_CertifyKey(key, aik, &pValidationData));

    // copy modulus into out
    keyOut->publicKey.size   = mod_size;
    keyOut->publicKey.buffer = (unsigned char*)calloc(mod_size, 1);
    if (keyOut->publicKey.buffer == NULL) {
        rc = -6;
        goto out;
    }
    memcpy(keyOut->publicKey.buffer, mod_blob, mod_size);

    // copy private blob intp out
    keyOut->privateBlob.size = blob_size;
    keyOut->privateBlob.buffer = (unsigned char*)calloc(blob_size, 1);
    if (keyOut->privateBlob.buffer == NULL) {
        rc = -7;
        free(keyOut->publicKey.buffer);
        goto out;
    } 
    memcpy(keyOut->privateBlob.buffer, blob_blob, blob_size);

    // copy key signature into out
    keyOut->keySignature.size = pValidationData.ulValidationDataLength;
    keyOut->keySignature.buffer = (unsigned char*)calloc(pValidationData.ulValidationDataLength, 1);
    if (keyOut->keySignature.buffer == NULL) {
        rc = -8;
        free(keyOut->publicKey.buffer);
        free(keyOut->keySignature.buffer);
        goto out;
    }
    memcpy(keyOut->keySignature.buffer, pValidationData.rgbValidationData, pValidationData.ulValidationDataLength);
    // copy key attestation into out

    keyOut->keyAttestation.size = pValidationData.ulDataLength;
    keyOut->keyAttestation.buffer = (unsigned char*)calloc(pValidationData.ulDataLength, 1);
    if (keyOut->keyAttestation.buffer == NULL) {
        rc = -9;
        free(keyOut->publicKey.buffer);
        free(keyOut->keySignature.buffer);
        free(keyOut->keyAttestation.buffer);
        goto out;
    }
    memcpy(keyOut->keyAttestation.buffer, pValidationData.rgbData, pValidationData.ulDataLength);
out:
    // Clean up all objects, if they were assigned
    if (tpm && tpm->context) {
        if (srk) {
            Tspi_Context_CloseObject(tpm->context, srk);
        }
        if (aik) {
            Tspi_Context_CloseObject(tpm->context, aik);
        }
        if (key) {
            Tspi_Context_CloseObject(tpm->context, key);
        }

        if (policy_srk) {
            Tspi_Context_CloseObject(tpm->context, policy_srk);
        }
        if (policy_aik) {
            Tspi_Context_CloseObject(tpm->context, policy_aik);
        }
        if (policy_srk) {
            Tspi_Context_CloseObject(tpm->context, policy_key);
        }

        if (mod_blob) {
            Tspi_Context_FreeMemory(tpm->context,  mod_blob);
        }
        if (blob_blob) {
            Tspi_Context_FreeMemory(tpm->context, blob_blob);
        }
        if (randomData) {
            Tspi_Context_FreeMemory(tpm->context, randomData);
        }

        if (pValidationData.rgbData) {
            Tspi_Context_FreeMemory(tpm->context, pValidationData.rgbData);
        }
        if (pValidationData.rgbValidationData) {
            Tspi_Context_FreeMemory(tpm->context, pValidationData.rgbValidationData);
        }
        if (pValidationData.rgbExternalData) {
            Tspi_Context_FreeMemory(tpm->context, pValidationData.rgbExternalData);
        }
    }
    return (int)rc;
}

int TpmUnbind12(TPM12* tpm, unsigned int* unboundLenOut, unsigned char** unboundDataOut, 
    unsigned int keyAuthLen, const unsigned char* keyAuth, 
    unsigned int privateKeyLen , const unsigned char* inKey, 
    unsigned int dataLen, const unsigned char* data) {
    TSS_RESULT      rc          = 0;
    TSS_HKEY        srk         = 0,
                    bk          = 0;
    TSS_HPOLICY     srkPolicy   = 0,
                    bkPolicy    = 0,
                    policyEnc   = 0;
    TSS_HENCDATA    encdata     = 0;
    UINT32          unboundLen  = 0;
    BYTE            *unbound    = NULL;
    // check parameters
    if (tpm == NULL) {
        return -1;
    }
    if (unboundDataOut == NULL) {
        return -2;
    }
    if (inKey == NULL) { 
        return -3;
    }
    if (keyAuth == NULL) {
        return -4;
    }
    if (data == NULL) {
        return -5;
    }
    CHECK(rc = loadSrk(tpm, &srk, &srkPolicy));

    // load binding key
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048  | TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE, &bk));
    CHECK(rc = Tspi_Context_LoadKeyByBlob(tpm->context, srk, privateKeyLen, (BYTE*)inKey, &bk));
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &bkPolicy));
    CHECK(rc = Tspi_Policy_SetSecret(bkPolicy, TSS_SECRET_MODE_PLAIN, keyAuthLen, (BYTE*)keyAuth));
    CHECK(rc = Tspi_Policy_AssignToObject(bkPolicy, bk));

    // Load the (encrypted) data blob

    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_BIND, &encdata));    
    CHECK(rc = Tspi_SetAttribData(encdata, TSS_TSPATTRIB_ENCDATA_BLOB, TSS_TSPATTRIB_ENCDATABLOB_BLOB, dataLen, (BYTE*)data));
    // CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &policyEnc));
    // CHECK(rc = Tspi_Policy_SetSecret(policyEnc, TSS_SECRET_MODE_PLAIN, 0, NULL))
    // CHECK(rc = Tspi_Policy_AssignToObject(policyEnc, encdata));
    // Unbind the blob
    CHECK(rc = Tspi_Data_Unbind(encdata, bk, &unboundLen, &unbound));
    // copy the unbound into out;
    *unboundLenOut = unboundLen;
    *unboundDataOut = calloc(unboundLen, 1);
    if (*unboundDataOut == NULL) {
        rc = -7;
        goto out;
    }
    memcpy(*unboundDataOut, unbound, unboundLen);
out:
    // Clean up all objects
    if (tpm && tpm->context) {
        if (srk) {
            Tspi_Context_CloseObject(tpm->context, srk);
        }
        if (bk) {
            Tspi_Context_CloseObject(tpm->context, bk);
        }

        if (srkPolicy) {
            Tspi_Context_CloseObject(tpm->context, srkPolicy);
        }
        if (bkPolicy) {
            Tspi_Context_CloseObject(tpm->context, bkPolicy);
        }
        if (policyEnc) {
            Tspi_Context_CloseObject(tpm->context, policyEnc);
        }

        if (encdata) {
            Tspi_Context_CloseObject(tpm->context, encdata);
        }

        if (unbound) {
            Tspi_Context_FreeMemory(tpm->context, unbound);
        }
    }

    return rc;
}

int TpmSign12(TPM12* tpm, unsigned int* signatureSizeOut, unsigned char** signatureOut,
 const unsigned int keyAuthLen, const unsigned char* keyAuth, 
 const unsigned int privateKeyLen, const unsigned char* privateKey,
 const unsigned int dataSize, const unsigned char* data) {
     if (signatureOut == NULL) {
         return -1;
     }
     if (keyAuth == NULL) {
         return -2;
     } 
     if (privateKey == NULL) {
         return -3;
     }
     if (data == NULL) {
         return -4;
     }

     if (dataSize != 20) {
         return -5;
     }

    TSS_RESULT      rc              = 0;
    TSS_HKEY        srk             = 0,
                    signingKey      = 0;
    TSS_HHASH       hash            = 0;
    TSS_HPOLICY     srkPolicy       = 0,
                    signKeyPolicy   = 0,
                    policyEnc       = 0;

    CHECK(rc = loadSrk(tpm, &srk, &srkPolicy));
     // load signing key
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_RSAKEY, TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048  | TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE, &signingKey));
    CHECK(rc = Tspi_Context_LoadKeyByBlob(tpm->context, srk, privateKeyLen, (BYTE*)privateKey, &signingKey));
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE, &signKeyPolicy));
    CHECK(rc = Tspi_Policy_SetSecret(signKeyPolicy, TSS_SECRET_MODE_PLAIN, keyAuthLen, (BYTE*)keyAuth));
    CHECK(rc = Tspi_Policy_AssignToObject(signKeyPolicy, signingKey));

    // hash the data
    CHECK(rc = Tspi_Context_CreateObject(tpm->context, TSS_OBJECT_TYPE_HASH, TSS_HASH_SHA1, &hash));
    CHECK(rc = Tspi_Hash_SetHashValue(hash, 20, (BYTE*)data));

    UINT32 sigSize;
    BYTE* sigBlob = NULL;
    // Sign the data
    CHECK(rc = Tspi_Hash_Sign(hash, signingKey, &sigSize, &sigBlob));
    *signatureSizeOut = sigSize;
    *signatureOut = malloc(sigSize);
    if (*signatureOut == NULL) {
        rc = -6;
        goto out;
    }
    memcpy(*signatureOut, sigBlob, sigSize);

out:
    // Clean up all objects
    if (tpm && tpm->context) {
        if (srk) {
            Tspi_Context_CloseObject(tpm->context, srk);
        }
        if (signingKey) {
            Tspi_Context_CloseObject(tpm->context, signingKey);
        } 
        if (srkPolicy) {
            Tspi_Context_CloseObject(tpm->context, srkPolicy);
        }
        if (signKeyPolicy) {
            Tspi_Context_CloseObject(tpm->context, signKeyPolicy);
        }
        if (policyEnc) {
            Tspi_Context_CloseObject(tpm->context, policyEnc);
        }
        if (hash) {
            Tspi_Context_CloseObject(tpm->context, hash);
        }
        if (sigBlob) {
            Tspi_Context_FreeMemory(tpm->context, sigBlob);
        }
    }

    return rc;
}