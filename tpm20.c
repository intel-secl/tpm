#include "tpm20.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define CHECK(rc) if ((rc) != TPM2_RC_SUCCESS) { fprintf(stderr, "Failure at: %s:%d\n", __FILE__, __LINE__); goto out; }

typedef enum { NO_PREFIX = 0, RM_PREFIX = 1 } printf_type;
typedef int (*TCTI_LOG_CALLBACK)( void *data, printf_type type, const char *format, ...);
typedef int (*TCTI_LOG_BUFFER_CALLBACK)( void *useriData, printf_type type, UINT8 *buffer, UINT32 length);

typedef struct {
    const char *hostname;
    uint16_t port;
    TCTI_LOG_CALLBACK logCallback;
    TCTI_LOG_BUFFER_CALLBACK logBufferCallback;
    void *logData;
} TCTI_SOCKET_CONF;

typedef TSS2_RC (*LEGACY_INIT_FN)(TSS2_TCTI_CONTEXT*, size_t*, const TCTI_SOCKET_CONF*, const uint8_t);

void TpmClose20(TPM20* tpm) {
    if (tpm != NULL) {
        if (tpm->tcti) {
            Tss2_Tcti_Finalize(tpm->tcti);
            free(tpm->tcti);
        }
        if (tpm->context) {
            Tss2_Sys_Finalize(tpm->context);
            free(tpm->context);
        }
        if (tpm->libTcti) {
            dlclose(tpm->libTcti);
        }
    }
}

extern int TSS2_LEGACY;
int TpmOpen20(TPM20* tpm, TCTI tctiType) {
    if (tpm == NULL) {
        return -1;
    }
    tpm->tcti = NULL;
    tpm->libTcti = NULL;
    tpm->context = NULL;

    if (tctiType == LEGACY) {
        TSS2_LEGACY = 1;
        tpm->libTcti = dlopen("libtcti-socket.so", RTLD_LAZY);
        if (tpm->libTcti == NULL) {
            return -2;
        }
        TCTI_SOCKET_CONF conf = {
            .hostname = "localhost",
            .port = 2321
        };
        LEGACY_INIT_FN fn = (LEGACY_INIT_FN)dlsym(tpm->libTcti, "InitSocketTcti");
        if (fn == NULL) {
            return -3;
        }
        size_t size;
        TPM2_RC rc = fn(NULL, &size, &conf, 0);
        tpm->tcti = (TSS2_TCTI_CONTEXT*)calloc(size, 1);
        if (tpm->tcti == NULL) {
            return -4;
        }
        // call init again
        rc = fn(tpm->tcti, &size, &conf, 0);
        if (rc != TPM2_RC_SUCCESS) {
            return -5;
        }
    } else if(tctiType == ABRMD || tctiType == SOCKET) {
        TSS2_LEGACY = 0;
        const char* tctiName = tctiType == ABRMD ? "libtss2-tcti-tabrmd.so" : "libtss2-tcti-mssim.so";
        tpm->libTcti = dlopen(tctiName, RTLD_LAZY);
        if (tpm->libTcti == NULL) {
            return -6;
        }
        TSS2_TCTI_INFO_FUNC infoFn = (TSS2_TCTI_INFO_FUNC)dlsym(tpm->libTcti, TSS2_TCTI_INFO_SYMBOL);
        if (infoFn == NULL) {
            return -7;
        }
        const TSS2_TCTI_INFO* info = infoFn();
        size_t size;
        TPM2_RC rc = info->init(NULL, &size, NULL); 
        if (rc != TPM2_RC_SUCCESS) {
            return -8;
        }
        tpm->tcti = (TSS2_TCTI_CONTEXT*)calloc(size, 1);
        if (tpm->tcti == NULL) {
            return -9;
        }
        rc = info->init(tpm->tcti, &size, NULL);
        if (rc != TPM2_RC_SUCCESS) {
            return -10;
        }
    } else {
        // Unknown TCTI type
        return -11;
    }
    // setup TSS2 SYS CONTEXT
    size_t size = Tss2_Sys_GetContextSize(0);
    tpm->context = (TSS2_SYS_CONTEXT*)calloc(size, 1);
    if (tpm->context == NULL) {
        return -12;
    }
    TSS2_ABI_VERSION abiv = TSS2_ABI_VERSION_CURRENT;
    TSS2_RC rc = Tss2_Sys_Initialize(tpm->context, size, tpm->tcti, &abiv);
    if (rc != TPM2_RC_SUCCESS) {
        return -13;
    }
    return rc;
}

int TpmCreateCertifiedKey20(TPM20* tpm, CertifiedKey20* keyOut, Usage usage, unsigned int keyAuthLen, unsigned char keyAuth[], unsigned int parentAuthLen, const unsigned char parentAuth[]) {
    // Validate arguments
    if (tpm == NULL) {
        return -1;
    }
    if (keyAuth == NULL) {
        return -2;
    } 
    if (usage != BINDING && usage != SIGNING) {
        return -3;
    }
    if (keyAuthLen > sizeof(((TPM2B_AUTH*)0)->buffer)) {
        return -4;
    }
    if (parentAuthLen > sizeof(((TPM2B_AUTH*)0)->buffer)) {
        return -5;
    }
    if (keyAuth == NULL) {
        return -7;
    }
    if (parentAuth == NULL) {
        return -8;
    }

    const TPMI_DH_OBJECT srkHandle = 0x81000000;
    const TPMI_DH_OBJECT aikHandle = 0x81018000;
    TSS2L_SYS_AUTH_COMMAND authSession = {
        .count = 1, .auths = {{
            .sessionHandle = TPM2_RS_PW,
        }}
    };
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    TPM2B_AUTH keyAuthCmd = {
        .size = keyAuthLen
    };
    memcpy(keyAuthCmd.buffer, keyAuth, keyAuthLen);
    inSensitive.sensitive.userAuth = keyAuthCmd;
    uint32_t typeFlag = usage == BINDING ? TPMA_OBJECT_DECRYPT : TPMA_OBJECT_SIGN_ENCRYPT;
    TPM2B_PUBLIC inPublic = {
        .publicArea = {
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = typeFlag|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH,
            .type = TPM2_ALG_RSA,
            .parameters = {
                .rsaDetail = {
                    .symmetric = {
                        .algorithm = TPM2_ALG_NULL
                    },
                    .scheme = {
                        .scheme = TPM2_ALG_NULL
                    },
                    .keyBits = 2048,
                    .exponent = 0
                }
            },
            .unique = {
                .rsa = {
                    .size = 0
                }
            }
        }
    };
    TPM2B_DATA outsideInfo = {};
    TPML_PCR_SELECTION creationPCR = {
        .count = 0
    };
    TPM2B_PUBLIC    outPublic = {};
    TPM2B_PRIVATE   outPrivate = {
        .size = sizeof(((TPM2B_PRIVATE*)0)->buffer)
    };
    TPM2B_CREATION_DATA creationData = {};
    TPM2B_DIGEST creationHash = {
        .size = sizeof(((TPM2B_DIGEST*)0)->buffer)
    };
    TPMT_TK_CREATION creationTicket = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2_RC rc;

    do {
        rc = Tss2_Sys_Create(tpm->context, srkHandle, &authSession,
                         &inSensitive, &inPublic, &outsideInfo, 
                         &creationPCR, &outPrivate, &outPublic, 
                         &creationData, &creationHash, &creationTicket,
                         &sessionsDataOut);
    } while (rc == TPM2_RC_RETRY);
    
    if (rc != TPM2_RC_SUCCESS) {
        return rc;
    }
    
    TPM2_HANDLE loadedHandle = 0;
    TPM2B_NAME name;
    CHECK(rc = Tss2_Sys_Load(tpm->context, srkHandle, &authSession, &outPrivate, &outPublic, &loadedHandle, &name, &sessionsDataOut));
    TSS2L_SYS_AUTH_COMMAND authSession2 = {
        .count = 2,
        .auths = {
            {
                .sessionHandle = TPM2_RS_PW,
                .hmac = {
                    .size = parentAuthLen
                }
            },
            {
                .sessionHandle = TPM2_RS_PW,
                .hmac = {
                    .size = keyAuthLen
                }
            }
        }
    };
    memcpy(authSession2.auths[0].hmac.buffer, parentAuth, parentAuthLen);
    memcpy(authSession2.auths[1].hmac.buffer, keyAuth, keyAuthLen);
    TPM2B_DATA qualifyingData = {
        .size = 4,
        .buffer = { 0x00, 0xff, 0x55,0xaa }
    };
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_RSASSA,
        .details = {
            .rsassa = {
                .hashAlg = TPM2_ALG_SHA256
            }
        }
    };
    TPM2B_ATTEST certifyInfo = {};
    TPMT_SIGNATURE signature = {};
    CHECK(rc = Tss2_Sys_Certify(tpm->context, loadedHandle, aikHandle, &authSession2, &qualifyingData, &inScheme, &certifyInfo, &signature, &sessionsDataOut));
    
    // allocate buffers
    keyOut->publicKey.buffer = (unsigned char*)calloc(sizeof(TPM2B_PUBLIC), 1);
    if (keyOut->publicKey.buffer == NULL) {
        return -9;
    }
    keyOut->privateBlob.buffer = (unsigned char*)calloc(sizeof(TPM2B_PRIVATE), 1);
    if (keyOut->privateBlob.buffer == NULL) {
        free(keyOut->publicKey.buffer);
        return -10;
    }
    keyOut->keySignature.buffer = (unsigned char*)calloc(sizeof(TPMT_SIGNATURE),1 );
    if (keyOut->keySignature.buffer == NULL) {
        free(keyOut->publicKey.buffer);
        free(keyOut->privateBlob.buffer);
        return -11;
    }
    keyOut->keyAttestation.buffer = (unsigned char*)calloc(sizeof(TPM2B_ATTEST), 1);
    if (keyOut->keyAttestation.buffer == NULL) {
        free(keyOut->publicKey.buffer);
        free(keyOut->privateBlob.buffer);
        free(keyOut->keySignature.buffer);
        return -12;
    }
    keyOut->keyName.buffer = (unsigned char*)calloc(sizeof(TPM2B_NAME), 1);
    if (keyOut->keyName.buffer == NULL) {
        free(keyOut->publicKey.buffer);
        free(keyOut->privateBlob.buffer);
        free(keyOut->keySignature.buffer);
        free(keyOut->keyAttestation.buffer);
        return -13;
    }

    size_t written = 0;
    Tss2_MU_TPM2B_PUBLIC_Marshal(&outPublic, keyOut->publicKey.buffer, sizeof(TPM2B_PUBLIC), &written);
    keyOut->publicKey.size = written;
    written = 0;
    
    Tss2_MU_TPM2B_PRIVATE_Marshal(&outPrivate, keyOut->privateBlob.buffer, sizeof(TPM2B_PRIVATE), &written);
    keyOut->privateBlob.size = written;
    written = 0;

    Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, keyOut->keySignature.buffer, sizeof(TPMT_SIGNATURE), &written);
    keyOut->keySignature.size = written;
    written = 0;

    Tss2_MU_TPM2B_ATTEST_Marshal(&certifyInfo, keyOut->keyAttestation.buffer, sizeof(TPM2B_ATTEST), &written);
    keyOut->keyAttestation.size = written;
    written = 0;

    Tss2_MU_TPM2B_NAME_Marshal(&name, keyOut->keyName.buffer, sizeof(TPM2B_NAME), &written);
    keyOut->keyName.size = written;
out:
    Tss2_Sys_FlushContext(tpm->context, loadedHandle);
    return rc;
}

int TpmUnbind20(TPM20* tpm, unsigned int* unboundLenOut, unsigned char** unboundDataOut, unsigned int privateKeyLen , const unsigned char* inPrivateKey, unsigned int publicKeyLen, const unsigned char* inPublicKey, unsigned int keyAuthLen, const unsigned char* keyAuth, unsigned int dataLen, const unsigned char* data) {
    // Validate arguments
    if (tpm == NULL) {
        return -1;
    }
    if (unboundDataOut == NULL) {
        return -2;
    }
    if (inPrivateKey == NULL) { 
        return -3;
    }
    if (inPublicKey == NULL) {
        return -4;
    }
    if (keyAuth == NULL) {
        return -5;
    }
    if (data == NULL) {
        return -6;
    }

    // CHECK LENS

    // load key
    const TPMI_DH_OBJECT srkHandle = 0x81000000;
    TSS2L_SYS_AUTH_COMMAND authSession = {
        .count = 1, .auths = {{
            .sessionHandle = TPM2_RS_PW,
        }}
    };
    memcpy(authSession.auths[0].hmac.buffer, keyAuth, keyAuthLen);
    TPM2_HANDLE bindingKeyHandle;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_NAME name = {
        .size = 0
    };

    TSS2_RC rc;
    TPM2B_PRIVATE inPrivate;
    TPM2B_PUBLIC inPublic;
    size_t offset = 0;
    Tss2_MU_TPM2B_PRIVATE_Unmarshal(inPrivateKey, privateKeyLen, &offset, &inPrivate);
    offset = 0;
    Tss2_MU_TPM2B_PUBLIC_Unmarshal(inPublicKey, publicKeyLen, &offset, &inPublic);
    CHECK(rc = Tss2_Sys_Load(tpm->context, srkHandle, &authSession, &inPrivate, &inPublic, &bindingKeyHandle, &name, &sessionsDataOut));
    TPM2B_PUBLIC_KEY_RSA cipherText = {
        .size = dataLen
    };
    memcpy(cipherText.buffer, data, dataLen);

    TPMT_RSA_DECRYPT scheme = {
        .scheme = TPM2_ALG_RSAES
    };

    TPM2B_PUBLIC_KEY_RSA message = {
        .size = sizeof(((TPM2B_PUBLIC_KEY_RSA*)0)->buffer)
    };
    TPM2B_DATA label = {
        .size = 0
    };
    CHECK(rc = Tss2_Sys_RSA_Decrypt(tpm->context, bindingKeyHandle, &authSession, &cipherText, &scheme, &label, &message, &sessionsDataOut));
    *unboundLenOut = message.size;
    *unboundDataOut = (unsigned char*)calloc(message.size, 1);
    if (*unboundDataOut == NULL) {
        rc = -6;
        goto out;
    }
    memcpy(*unboundDataOut, message.buffer, message.size);
out:
    Tss2_Sys_FlushContext(tpm->context, bindingKeyHandle);
    return rc;
}