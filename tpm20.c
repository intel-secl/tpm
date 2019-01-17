#include "tpm.h"
#include "tss2.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define CHECK(rc) if ((rc) != TPM2_RC_SUCCESS) { fprintf(stderr, "Failure at: %s:%d\n", __FILE__, __LINE__); goto out; }


// TSS2 changed several structure definitions, so to support the ancient version TrustAgent has, we need to create some old instances of structs
typedef struct {
    uint8_t cmdAuthsCount;
    TPMS_AUTH_COMMAND **cmdAuths;
} TSS2_SYS_CMD_AUTHS;

typedef struct {
    uint8_t rspAuthsCount;
    TPMS_AUTH_RESPONSE **rspAuths;
} TSS2_SYS_RSP_AUTHS;

typedef struct {
    TPMI_SH_AUTH_SESSION	sessionHandle;	 /* the session handle  */
	TPM2B_NONCE	nonce;	 /* the session nonce may be the Empty Buffer  */
	//TPMA_SESSION	sessionAttributes;	 /* the session attributes  */
    UINT32 sessionsAttributes;
	TPM2B_AUTH	hmac;	 /* either an HMAC a password or an EmptyAuth  */
} TPMS_AUTH_COMMAND_LEGACY;

typedef	struct {
	TPM2B_NONCE	nonce;	 /* the session nonce may be the Empty Buffer  */
	TPMA_SESSION	sessionAttributes;	 /* the session attributes  */
	TPM2B_AUTH	hmac;	 /* either an HMAC or an EmptyAuth  */
} TPMS_AUTH_RESPONSE_LEGACY;

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

typedef struct {
    const char *device_path;
    TCTI_LOG_CALLBACK logCallback;
    void *logData;
} TCTI_DEVICE_CONF;

typedef TSS2_RC (*SOCKET_LEGACY_INIT_FN)(TSS2_TCTI_CONTEXT*, size_t*, const TCTI_SOCKET_CONF*, const uint8_t);
typedef TSS2_RC (*TABRMD_LEGACY_INIT_FN)(TSS2_TCTI_CONTEXT*, size_t*);

void TpmClose20(TPM20* tpm) {
    if (tpm != NULL) {
        if (tpm->tcti) {
            Tss2_Tcti_Finalize(tpm->tcti);
            free(tpm->tcti);
        }
        if (tpm->context) {
            _Tss2_Sys_Finalize(tpm);
            free(tpm->context);
        }
        if (tpm->libTcti) {
            dlclose(tpm->libTcti);
        }
    }
}

int TpmOpen20(TPM20* tpm, TCTI tctiType) {
    TSS2_ABI_VERSION *abiv;
    TSS2_ABI_VERSION abiLegacy = {1,1,1,1};
    TSS2_ABI_VERSION abiModern = TSS2_ABI_VERSION_CURRENT;
    if (tpm == NULL) {
        return -1;
    }
    tpm->tcti = NULL;
    tpm->libTcti = NULL;
    tpm->context = NULL;

    if (tctiType == SOCKET_LEGACY || tctiType == ABRMD_LEGACY) {
        //TSS2_LEGACY = 1;
        tpm->legacy = 1;
        tpm->libTss2 = dlopen(LIB_SAPI, RTLD_LAZY);
        if (tpm->libTss2 == NULL) {
            return -2;
        }
        abiv = &abiLegacy;
        tpm->libTcti = tctiType == SOCKET_LEGACY ? dlopen(LIB_TCTI_SOCKET_LEGACY, RTLD_LAZY) : dlopen(LIB_TCTI_TABRMD_LEGACY, RTLD_LAZY);
        if (tpm->libTcti == NULL) {
            return -3;
        }
        if (tctiType == SOCKET_LEGACY) {
            TCTI_SOCKET_CONF conf = {
                .hostname = "127.0.0.1",
                .port = 2323
            };
            SOCKET_LEGACY_INIT_FN fn = (SOCKET_LEGACY_INIT_FN)dlsym(tpm->libTcti, "InitSocketTcti");
            size_t size;
            TPM2_RC rc = fn(NULL, &size, &conf, 0);
            if (fn == NULL) {
                return -4;
            }
            tpm->tcti = (TSS2_TCTI_CONTEXT*)calloc(size, 1);
            if (tpm->tcti == NULL) {
                return -5;
            }
            // call init again
            rc = fn(tpm->tcti, &size, &conf, 0);
            if (rc != TPM2_RC_SUCCESS) {
                return -6;
            }
        } else {
            TCTI_DEVICE_CONF conf = {
                .device_path = "/dev/tpm0"
            };
            TABRMD_LEGACY_INIT_FN fn = (TABRMD_LEGACY_INIT_FN)dlsym(tpm->libTcti, "tss2_tcti_tabrmd_init");
            size_t size;
            TPM2_RC rc = fn(NULL, &size);
            if (fn == NULL) {
                return -4;
            }
            tpm->tcti = (TSS2_TCTI_CONTEXT*)calloc(size, 1);
            if (tpm->tcti == NULL) {
                return -5;
            }
            // call init again
            rc = fn(tpm->tcti, &size);
            if (rc != TPM2_RC_SUCCESS) {
                return -6;
            }
        }
    } else if(tctiType == ABRMD || tctiType == SOCKET) {
        tpm->legacy = 0;
        abiv = &abiModern;
        tpm->libTss2 = dlopen(LIB_TSS2_SYS, RTLD_LAZY) ?: dlopen(LIB_SAPI, RTLD_LAZY);
        if (tpm->libTss2 == NULL) {
            return -7;
        }
        const char* tctiName = tctiType == ABRMD ? LIB_TCTI_TABRMD : LIB_TCTI_MSSIM;
        if (tctiType == ABRMD)
            tpm->libTcti = dlopen(LIB_TCTI_TABRMD, RTLD_LAZY);
        else 
            tpm->libTcti = dlopen(LIB_TCTI_MSSIM, RTLD_LAZY);
        if (tpm->libTcti == NULL) {
            return -8;
        }
        TSS2_TCTI_INFO_FUNC infoFn = (TSS2_TCTI_INFO_FUNC)dlsym(tpm->libTcti, TSS2_TCTI_INFO_SYMBOL);
        if (infoFn == NULL) {
            return -9;
        }
        const TSS2_TCTI_INFO* info = infoFn();
        size_t size;
        TPM2_RC rc = info->init(NULL, &size, NULL); 
        if (rc != TPM2_RC_SUCCESS) {
            return -10;
        }
        tpm->tcti = (TSS2_TCTI_CONTEXT*)calloc(size, 1);
        if (tpm->tcti == NULL) {
            return -11;
        }
        rc = info->init(tpm->tcti, &size, NULL);
        if (rc != TPM2_RC_SUCCESS) {
            return -12;
        }
    } else {
        // Unknown TCTI type
        return -13;
    }
    // setup TSS2 SYS CONTEXT
    size_t size = _Tss2_Sys_GetContextSize(tpm, 0);
    tpm->context = (TSS2_SYS_CONTEXT*)calloc(size, 1);
    if (tpm->context == NULL) {
        return -14;
    }
    TSS2_RC rc = _Tss2_Sys_Initialize(tpm, size, tpm->tcti, abiv);
    if (rc != TPM2_RC_SUCCESS) {
        return -15;
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
    TSS2L_SYS_AUTH_COMMAND nullSession = {
        .count = 1, .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .hmac = {
                .size = 0
            },
            .nonce = {
                .size = 0
            }
        }}
    };

    TPMS_AUTH_COMMAND_LEGACY nullAuthCommandLegacy = {
        .sessionHandle = TPM2_RS_PW,
        .hmac = {
            .size = 0
        },
        .nonce = {
            .size = 0
        }
    };
    TPMS_AUTH_COMMAND_LEGACY *legacyTpmsAuth[1] = {&nullAuthCommandLegacy};
    TSS2_SYS_CMD_AUTHS nullSessionLegacy = {
        .cmdAuthsCount = 1,
        .cmdAuths = (void*)&legacyTpmsAuth[0]
    };
    TPM2B_SENSITIVE_CREATE inSensitive = {};
    TPM2B_AUTH keyAuth2B = {
        .size = keyAuthLen
    };
    memcpy(keyAuth2B.buffer, keyAuth, keyAuthLen);
    inSensitive.sensitive.userAuth = keyAuth2B;
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
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {
        .count = 1,
        .auths = {{}}
    };
    TPMS_AUTH_RESPONSE_LEGACY authResponse = {0};
    TPMS_AUTH_RESPONSE_LEGACY *legacyRspAuths[1] = {&authResponse};
    TSS2_SYS_RSP_AUTHS sessionsOutLegacy = {
        .rspAuthsCount = 1,
        .rspAuths = (void*)&legacyRspAuths[0]
    };
    TPM2_RC rc;
    do {
        rc = _Tss2_Sys_Create(tpm, srkHandle, tpm->legacy ? (const void*)&nullSessionLegacy : &nullSession,
                         &inSensitive, &inPublic, &outsideInfo, 
                         &creationPCR, &outPrivate, &outPublic, 
                         &creationData, &creationHash, &creationTicket,
                         tpm->legacy ? (TSS2L_SYS_AUTH_RESPONSE*)&sessionsOutLegacy : &sessionsDataOut);
    } while (rc == TPM2_RC_RETRY);
    CHECK(rc);
    TPM2_HANDLE loadedHandle = 0;
    TPM2B_NAME name = { 
        .size = sizeof(TPM2B_NAME)-2, 
    };

    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut2 = {
        .count = 1,
        .auths = {{}}
    };
    TPMS_AUTH_RESPONSE_LEGACY authResponse2;
    TPMS_AUTH_RESPONSE_LEGACY *legacyRspAuths2[3] = {&authResponse2};
    TSS2_SYS_RSP_AUTHS sessionsOutLegacy2 = {
        .rspAuthsCount = 1,
        .rspAuths = (void*)&legacyRspAuths2[0]
    };

    CHECK(rc = _Tss2_Sys_Load(tpm, srkHandle, tpm->legacy ? (const TSS2L_SYS_AUTH_COMMAND*)&nullSessionLegacy : &nullSession,
         &outPrivate, &outPublic, &loadedHandle, &name, tpm->legacy ? (TSS2L_SYS_AUTH_RESPONSE*)&sessionsOutLegacy2 : &sessionsDataOut));
    TPMS_AUTH_COMMAND_LEGACY parentAuthCmdLegacy = {
        .sessionHandle = TPM2_RS_PW,
        .hmac = {
            .size = parentAuthLen
        },
        .nonce = {
            .size = 0
        }
    };
    TPMS_AUTH_COMMAND_LEGACY keyAuthCmdLegacy = {
        .sessionHandle = TPM2_RS_PW,
        .hmac = {
            .size = keyAuthLen
        },
        .nonce = {
            .size = 0
        }
    };
    memcpy(parentAuthCmdLegacy.hmac.buffer, parentAuth, parentAuthLen);
    memcpy(keyAuthCmdLegacy.hmac.buffer, keyAuth, keyAuthLen);
    TPMS_AUTH_COMMAND_LEGACY *legacyAuthCmd[2] = {&keyAuthCmdLegacy, &parentAuthCmdLegacy};
    TSS2_SYS_CMD_AUTHS authSession2Legacy = {
        .cmdAuthsCount = 2,
        .cmdAuths = (void*)&legacyAuthCmd[0]
    };
    TSS2L_SYS_AUTH_COMMAND authSession2 = {
        .count = 2,
        .auths = {
            {
                .sessionHandle = TPM2_RS_PW,
                .hmac = {
                    .size = keyAuthLen
                }
            },
            {
                .sessionHandle = TPM2_RS_PW,
                .hmac = {
                    .size = parentAuthLen
                }
            }
        }
    };
    memcpy(authSession2.auths[0].hmac.buffer, keyAuth, keyAuthLen);
    memcpy(authSession2.auths[1].hmac.buffer, parentAuth, parentAuthLen);
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
    TPM2B_ATTEST certifyInfo = {
        .size = sizeof(TPM2B_ATTEST) - 2
    };
    TPMT_SIGNATURE signature = {};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut3= {
        .count = 2,
        .auths = {{}, {}}
    };
    TPMS_AUTH_RESPONSE *legacyRspAuths3[3] = {&sessionsDataOut3.auths[0], &sessionsDataOut3.auths[1]};
    TSS2_SYS_RSP_AUTHS sessionsOutLegacy3 = {
        .rspAuthsCount = 2,
        .rspAuths = (void*)&legacyRspAuths3[0]
    };

    CHECK(rc = _Tss2_Sys_Certify(tpm, loadedHandle, aikHandle, tpm->legacy ? (void*)&authSession2Legacy : &authSession2, 
        &qualifyingData, &inScheme, &certifyInfo, &signature, tpm->legacy ? (void*)&sessionsOutLegacy3 : &sessionsDataOut));
    
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
    _Tss2_Sys_FlushContext(tpm, loadedHandle);
    return rc;
}

int TpmUnbind20(TPM20* tpm, unsigned int* unboundLenOut, unsigned char** unboundDataOut, 
    unsigned int keyAuthLen, const unsigned char* keyAuth, 
    unsigned int privateKeyLen , const unsigned char* inPrivateKey, 
    unsigned int publicKeyLen, const unsigned char* inPublicKey, 
    unsigned int dataLen, const unsigned char* data) {
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
    if (keyAuthLen > sizeof(((TPM2B_AUTH*)0)->buffer)) {
        return -7;
    }
    // load key
    TSS2L_SYS_AUTH_COMMAND nullSession = {
        .count = 1, .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .hmac = {
                .size = 0
            },
            .nonce = {
                .size = 0
            }
        }}
    };

    TPMS_AUTH_COMMAND_LEGACY nullAuthCommandLegacy = {
        .sessionHandle = TPM2_RS_PW,
        .hmac = {
            .size = 0
        },
        .nonce = {
            .size = 0
        }
    };
    TPMS_AUTH_COMMAND_LEGACY *legacyTpmsAuth[1] = {&nullAuthCommandLegacy};
    TSS2_SYS_CMD_AUTHS nullSessionLegacy = {
        .cmdAuthsCount = 1,
        .cmdAuths = (void*)&legacyTpmsAuth[0]
    };

    const TPMI_DH_OBJECT srkHandle = 0x81000000;
    TSS2L_SYS_AUTH_COMMAND authSession = {
        .count = 1, .auths = {{
            .sessionHandle = TPM2_RS_PW,
                .hmac = {
                    .size = keyAuthLen
                },
        }}
    };
    memcpy(authSession.auths[0].hmac.buffer, keyAuth, keyAuthLen);

    TPMS_AUTH_COMMAND_LEGACY keyAuthCmdLegacy = {
        .sessionHandle = TPM2_RS_PW,
        .hmac = {
            .size = keyAuthLen
        },
        .nonce = {
            .size = 0
        }
    };
    memcpy(keyAuthCmdLegacy.hmac.buffer, keyAuth, keyAuthLen);
    TPMS_AUTH_COMMAND_LEGACY *legacyAuthCmd[1] = {&keyAuthCmdLegacy};
    TSS2_SYS_CMD_AUTHS authSessionLegacy = {
        .cmdAuthsCount = 1,
        .cmdAuths = (void*)&legacyAuthCmd[0]
    };
    TPM2_HANDLE bindingKeyHandle;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    TPM2B_NAME name = {
        .size = sizeof(TPM2B_NAME)-2
    };
    TPMS_AUTH_RESPONSE_LEGACY authResponse = {0};
    TPMS_AUTH_RESPONSE_LEGACY *legacyRspAuths[1] = {&authResponse};
    TSS2_SYS_RSP_AUTHS sessionsOutLegacy = {
        .rspAuthsCount = 1,
        .rspAuths = (void*)&legacyRspAuths[0]
    };

    TSS2_RC rc = 0;
    TPM2B_PRIVATE inPrivate = {
    };
    TPM2B_PUBLIC inPublic = {
    };
    size_t offset = 0;
    CHECK(rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(inPrivateKey, privateKeyLen, &offset, &inPrivate));
    offset = 0;
    CHECK(rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(inPublicKey, publicKeyLen, &offset, &inPublic));
    CHECK(rc = _Tss2_Sys_Load(tpm, srkHandle, tpm->legacy ? (const void*)&nullSessionLegacy : &nullSession, &inPrivate, &inPublic, &bindingKeyHandle, &name, tpm->legacy ? (TSS2L_SYS_AUTH_RESPONSE*)&sessionsOutLegacy : &sessionsDataOut));
    TPM2B_PUBLIC_KEY_RSA cipherText = {
        .size = dataLen
    };
    memcpy(cipherText.buffer, data, dataLen);

    TPMT_RSA_DECRYPT scheme = {
        .scheme = TPM2_ALG_OAEP
    };
    scheme.details.oaep.hashAlg = TPM2_ALG_SHA256;

    TPM2B_PUBLIC_KEY_RSA message = {
        .size = sizeof(((TPM2B_PUBLIC_KEY_RSA*)0)->buffer)
    };
    TPM2B_DATA label = {
        .size = sizeof("TPM2"),
        .buffer = "TPM2",
    };
    CHECK(rc = _Tss2_Sys_RSA_Decrypt(tpm, bindingKeyHandle, tpm->legacy ? (const void*)&authSessionLegacy : &authSession, &cipherText, &scheme, &label, &message, tpm->legacy ? (TSS2L_SYS_AUTH_RESPONSE*)&sessionsOutLegacy : &sessionsDataOut));
    *unboundLenOut = message.size;
    *unboundDataOut = (unsigned char*)calloc(message.size, 1);
    if (*unboundDataOut == NULL) {
        rc = -6;
        goto out;
    }
    memcpy(*unboundDataOut, message.buffer, message.size);
out:
    _Tss2_Sys_FlushContext(tpm, bindingKeyHandle);
    return rc;
}

TPM2_ALG_ID GoHash2TpmHash(int algId) {
    switch (algId) {
        case 3:
            return TPM2_ALG_SHA1;
        case 5:
            return TPM2_ALG_SHA256;
        case 6:
            return TPM2_ALG_SHA384;
        case 7:
            return TPM2_ALG_SHA512;
        default:
            return 0;
    }
} 

int HashSize(TPM2_ALG_ID hashAlg) {
    /* Hash algorithm sizes */
    // #define TPM2_SHA_DIGEST_SIZE     20
    // #define TPM2_SHA1_DIGEST_SIZE    20
    // #define TPM2_SHA256_DIGEST_SIZE  32
    // #define TPM2_SHA384_DIGEST_SIZE  48
    // #define TPM2_SHA512_DIGEST_SIZE  64
    // #define TPM2_SM3_256_DIGEST_SIZE 32
    switch (hashAlg) {
        case TPM2_ALG_SHA1:
            return TPM2_SHA_DIGEST_SIZE;
        case TPM2_ALG_SHA256:
            return TPM2_SHA256_DIGEST_SIZE;
        case TPM2_ALG_SHA384:
            return TPM2_SHA384_DIGEST_SIZE;
        case TPM2_SHA512_DIGEST_SIZE:
            return TPM2_SHA512_DIGEST_SIZE;
        default:
            return 0;
    }
}

int TpmSign20(TPM20* tpm, unsigned int* signatureSizeOut, unsigned char** signatureOut,
    const unsigned int keyAuthLen, const unsigned char* keyAuth, 
    const unsigned int privateKeyLen, const unsigned char* privateKey,
    const unsigned int publicKeyLen, const unsigned char* publicKey,
    const unsigned int dataSize, const unsigned char* data, int algId) {
    
    if (tpm == NULL) {
        return -1;
    }
    if (signatureSizeOut == NULL) {
        return -2;
    }
    if (signatureOut == NULL) {
        return -3;
    }
    if (keyAuth == NULL) {
        return -4;
    }
    if (privateKey == NULL) {
        return -5;
    }
    if (publicKey == NULL) {
        return -6;
    }
    if (data == NULL) {
        return -7;
    }
    if (keyAuthLen > sizeof(((TPM2B_AUTH*)0)->buffer)) {
        return -8;
    }

    TPM2_ALG_ID hashAlg = GoHash2TpmHash(algId);
    if (hashAlg == 0) {
        return -9;
    }

    int hashLen = HashSize(hashAlg);
    if (hashLen != dataSize) {
        return -10;
    }

    // load keys
    TSS2L_SYS_AUTH_COMMAND nullSession = {
        .count = 1, .auths = {{
            .sessionHandle = TPM2_RS_PW,
            .hmac = {
                .size = 0
            },
            .nonce = {
                .size = 0
            }
        }}
    };

    TPMS_AUTH_COMMAND_LEGACY nullAuthCommandLegacy = {
        .sessionHandle = TPM2_RS_PW,
        .hmac = {
            .size = 0
        },
        .nonce = {
            .size = 0
        }
    };
    TPMS_AUTH_COMMAND_LEGACY *legacyTpmsAuth[1] = {&nullAuthCommandLegacy};
    TSS2_SYS_CMD_AUTHS nullSessionLegacy = {
        .cmdAuthsCount = 1,
        .cmdAuths = (void*)&legacyTpmsAuth[0]
    };

    const TPMI_DH_OBJECT srkHandle = 0x81000000;
    TSS2L_SYS_AUTH_COMMAND authSession = {
        .count = 1, .auths = {{
            .sessionHandle = TPM2_RS_PW,
                .hmac = {
                    .size = keyAuthLen
                },
        }}
    };
    memcpy(authSession.auths[0].hmac.buffer, keyAuth, keyAuthLen);

    TPMS_AUTH_COMMAND_LEGACY keyAuthCmdLegacy = {
        .sessionHandle = TPM2_RS_PW,
        .hmac = {
            .size = keyAuthLen
        },
        .nonce = {
            .size = 0
        }
    };
    memcpy(keyAuthCmdLegacy.hmac.buffer, keyAuth, keyAuthLen);
    TPMS_AUTH_COMMAND_LEGACY *legacyAuthCmd[1] = {&keyAuthCmdLegacy};
    TSS2_SYS_CMD_AUTHS authSessionLegacy = {
        .cmdAuthsCount = 1,
        .cmdAuths = (void*)&legacyAuthCmd[0]
    };
    TPM2_HANDLE signingKeyHandle = 0;
    TPM2B_NAME name = {
        .size = sizeof(TPM2B_NAME)-2
    };
    TSS2_RC rc = 0;
    TPM2B_PRIVATE inPrivate = {
    };
    TPM2B_PUBLIC inPublic = {
    };
    size_t offset = 0;
    CHECK(rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(privateKey, privateKeyLen, &offset, &inPrivate));
    offset = 0;
    CHECK(rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(publicKey, publicKeyLen, &offset, &inPublic));
    CHECK(rc = _Tss2_Sys_Load(tpm, srkHandle, tpm->legacy ? (const void*)&nullSessionLegacy : &nullSession, 
                                &inPrivate, &inPublic, &signingKeyHandle, &name, NULL));

    TPM2B_MAX_BUFFER dataIn;
    dataIn.size = dataSize;
    memcpy(dataIn.buffer, data, dataSize);
    TPM2B_DIGEST hash;
    hash.size = hashLen;
    memcpy(hash.buffer, data, hashLen);
    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_RSASSA
    };
    scheme.details.rsassa.hashAlg = hashAlg;
    TPMT_SIGNATURE sig;
    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
    };
    CHECK(rc = _Tss2_Sys_Sign(tpm, signingKeyHandle, tpm->legacy ? (const void*)&authSessionLegacy : &authSession, 
                                &hash /*digest*/, &scheme /* sig scheme */, &validation /* TK_HAHSHCHECK*/, &sig /*SIG*/,
                               NULL));
    *signatureSizeOut = sig.signature.rsassa.sig.size;
    *signatureOut = (unsigned char*)malloc(sig.signature.rsassa.sig.size);
    if (*signatureOut == NULL) {
        rc = -12;
        goto out;
    }
    memcpy(*signatureOut, sig.signature.rsassa.sig.buffer, sig.signature.rsassa.sig.size);
out: 
    _Tss2_Sys_FlushContext(tpm, signingKeyHandle);
    return rc;
}