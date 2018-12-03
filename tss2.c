#include "tpm.h"
#include <tss2/tss2_sys.h>
#include <tss2/tss2_mu.h>
#include <dlfcn.h>
#include <stdio.h>
#include "util.h"

int TSS2_LEGACY = 1;

void* getLibSys() {
    static void* libSys = NULL;
    if (libSys == NULL) {
        libSys = dlopen(LIB_TSS2_SYS, RTLD_LAZY);
        if(libSys == NULL) {
            panic(dlerror());
        }
    }
    return libSys;
}

void* getLibSapi() {
    static void* libsapi = NULL;
    if (libsapi == NULL) {
        libsapi = dlopen(LIB_SAPI, RTLD_LAZY);
        if (libsapi == NULL) {
            panic(dlerror());
        }
    }
    return libsapi;
}

void* getLibTss2() {
    if (TSS2_LEGACY) {
        return getLibSapi();
    } else {
        return getLibSys();
    }
}

void* getLibMu() {
    if (TSS2_LEGACY == 1) {
        return getLibSapi();
    } else {
        static void* libMu = NULL;
        if (libMu == NULL) {
            libMu = dlopen(LIB_TSS2_MU, RTLD_LAZY);
        }
        return libMu;
    }
}




#define RESOLVE_SYS(symbol) resolve(getLibTss2(), #symbol )
#define RESOLVE_MU(symbol) resolve(getLibMu(), #symbol )

size_t Tss2_Sys_GetContextSize(size_t maxCommandResponseSize) {
    size_t (*ptr)(size_t) = RESOLVE_SYS(Tss2_Sys_GetContextSize);
    return ptr(maxCommandResponseSize);
}

TSS2_RC Tss2_Sys_Initialize(TSS2_SYS_CONTEXT *sysContext,
                            size_t contextSize,
                            TSS2_TCTI_CONTEXT *tctiContext,
                            TSS2_ABI_VERSION *abiVersion) {
    TSS2_RC (*ptr)(TSS2_SYS_CONTEXT*, size_t, TSS2_TCTI_CONTEXT*, TSS2_ABI_VERSION*) = RESOLVE_SYS(Tss2_Sys_Initialize);
    return ptr(sysContext, contextSize, tctiContext, abiVersion);
}

void Tss2_Sys_Finalize(TSS2_SYS_CONTEXT *sysContext) {
    void (*ptr)(TSS2_SYS_CONTEXT*) = RESOLVE_SYS(Tss2_Sys_Finalize);
    return ptr(sysContext);
}

TSS2_RC Tss2_Sys_Create(TSS2_SYS_CONTEXT *sysContext,
                        TPMI_DH_OBJECT parentHandle,
                        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                        const TPM2B_SENSITIVE_CREATE *inSensitive,
                        const TPM2B_PUBLIC *inPublic,
                        const TPM2B_DATA *outsideInfo,
                        const TPML_PCR_SELECTION *creationPCR,
                        TPM2B_PRIVATE *outPrivate,
                        TPM2B_PUBLIC *outPublic,
                        TPM2B_CREATION_DATA *creationData,
                        TPM2B_DIGEST *creationHash,
                        TPMT_TK_CREATION *creationTicket,
                        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray
                        ) {
    TSS2_RC (*ptr)(TSS2_SYS_CONTEXT *,
                        TPMI_DH_OBJECT ,
                        TSS2L_SYS_AUTH_COMMAND const *,
                        const TPM2B_SENSITIVE_CREATE *,
                        const TPM2B_PUBLIC *inPulic,
                        const TPM2B_DATA *,
                        const TPML_PCR_SELECTION *,
                        TPM2B_PRIVATE *,
                        TPM2B_PUBLIC *,
                        TPM2B_CREATION_DATA *,
                        TPM2B_DIGEST *,
                        TPMT_TK_CREATION *,
                        TSS2L_SYS_AUTH_RESPONSE *
                        ) = RESOLVE_SYS(Tss2_Sys_Create);
    return ptr(sysContext, parentHandle, cmdAuthsArray, inSensitive, inPublic, outsideInfo, creationPCR,
                outPrivate, outPublic, creationData, creationHash, creationTicket, rspAuthsArray);
}

TSS2_RC Tss2_Sys_Load(TSS2_SYS_CONTEXT *sysContext,
                        TPMI_DH_OBJECT parentHandle,
                        TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                        const TPM2B_PRIVATE *inPrivate,
                        const TPM2B_PUBLIC *inPublic,
                        TPM2_HANDLE *objectHandle,
                        TPM2B_NAME *name,
                        TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray
                        ) {
    TSS2_RC (*ptr)(TSS2_SYS_CONTEXT *,
                        TPMI_DH_OBJECT ,
                        TSS2L_SYS_AUTH_COMMAND const *,
                        const TPM2B_PRIVATE *,
                        const TPM2B_PUBLIC *,
                        TPM2_HANDLE *,
                        TPM2B_NAME *,
                        TSS2L_SYS_AUTH_RESPONSE *) = RESOLVE_SYS(Tss2_Sys_Load);
    return ptr(sysContext, parentHandle, cmdAuthsArray, inPrivate, inPublic, objectHandle, name, rspAuthsArray);
}

TSS2_RC Tss2_Sys_FlushContext(TSS2_SYS_CONTEXT *sysContext, TPMI_DH_CONTEXT flushHandle) {
    TSS2_RC (*ptr)(TSS2_SYS_CONTEXT*, TPMI_DH_CONTEXT) = RESOLVE_SYS(Tss2_Sys_FlushContext);
    return ptr(sysContext, flushHandle);
}

TSS2_RC Tss2_Sys_Certify(TSS2_SYS_CONTEXT *sysContext,
                            TPMI_DH_OBJECT objectHandle,
                            TPMI_DH_OBJECT signHandle,
                            TSS2L_SYS_AUTH_COMMAND const *cmdAuthsArray,
                            const TPM2B_DATA *qualifyingData,
                            const TPMT_SIG_SCHEME *inScheme,
                            TPM2B_ATTEST *certifyInfo,
                            TPMT_SIGNATURE *signature,
                            TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {
    TSS2_RC (*ptr)(TSS2_SYS_CONTEXT *,
                            TPMI_DH_OBJECT ,
                            TPMI_DH_OBJECT ,
                            TSS2L_SYS_AUTH_COMMAND const *,
                            const TPM2B_DATA *,
                            const TPMT_SIG_SCHEME *,
                            TPM2B_ATTEST *,
                            TPMT_SIGNATURE *,
                            TSS2L_SYS_AUTH_RESPONSE *) = RESOLVE_SYS(Tss2_Sys_Certify);
    return ptr(sysContext, objectHandle, signHandle, cmdAuthsArray, qualifyingData, inScheme, 
                certifyInfo, signature, rspAuthsArray);
}

TSS2_RC Tss2_Sys_RSA_Decrypt(TSS2_SYS_CONTEXT *sysContext,
                                TPMI_DH_OBJECT keyHandle,
                                const TSS2L_SYS_AUTH_COMMAND *cmdAuthsArray,
                                const TPM2B_PUBLIC_KEY_RSA *cipherText,
                                const TPMT_RSA_DECRYPT *inScheme,
                                const TPM2B_DATA *label,
                                TPM2B_PUBLIC_KEY_RSA *message,
                                TSS2L_SYS_AUTH_RESPONSE *rspAuthsArray) {
    TSS2_RC (*ptr)(TSS2_SYS_CONTEXT *,
                                TPMI_DH_OBJECT ,
                                const TSS2L_SYS_AUTH_COMMAND *,
                                const TPM2B_PUBLIC_KEY_RSA *,
                                const TPMT_RSA_DECRYPT *,
                                const TPM2B_DATA *,
                                TPM2B_PUBLIC_KEY_RSA *,
                                TSS2L_SYS_AUTH_RESPONSE *) = RESOLVE_SYS(Tss2_Sys_RSA_Decrypt);
    return ptr(sysContext, keyHandle, cmdAuthsArray, cipherText, inScheme, label, message, rspAuthsArray);
}

// Marshaling and unmarshaling

TSS2_RC
Tss2_MU_TPM2B_ATTEST_Marshal(
    TPM2B_ATTEST const *src,
    uint8_t         buffer[],
    size_t          buffer_size,
    size_t         *offset) {
    TSS2_RC (*ptr)(TPM2B_ATTEST const *src,
                    uint8_t         buffer[],
                    size_t          buffer_size,
                    size_t         *offset) = RESOLVE_MU(Tss2_MU_TPM2B_ATTEST_Marshal);
    return ptr(src, buffer, buffer_size, offset);
}

TSS2_RC
Tss2_MU_TPM2B_NAME_Marshal(
    TPM2B_NAME const *src,
    uint8_t         buffer[],
    size_t          buffer_size,
    size_t         *offset) {
    
    TSS2_RC (*ptr)(TPM2B_NAME const *src,
                    uint8_t         buffer[],
                    size_t          buffer_size,
                    size_t         *offset) = RESOLVE_MU(Tss2_MU_TPM2B_NAME_Marshal);
    return ptr(src, buffer, buffer_size, offset);
}

TSS2_RC
Tss2_MU_TPM2B_PRIVATE_Marshal(
    TPM2B_PRIVATE const *src,
    uint8_t         buffer[],
    size_t          buffer_size,
    size_t         *offset) {
    
    TSS2_RC (*ptr)(TPM2B_PRIVATE const *src,
                    uint8_t         buffer[],
                    size_t          buffer_size,
                    size_t         *offset) = RESOLVE_MU(Tss2_MU_TPM2B_PRIVATE_Marshal);
    return ptr(src, buffer, buffer_size, offset);
}

TSS2_RC
Tss2_MU_TPM2B_PUBLIC_Marshal(
    TPM2B_PUBLIC const *src,
    uint8_t         buffer[],
    size_t          buffer_size,
    size_t         *offset) {
    
    TSS2_RC (*ptr)(TPM2B_PUBLIC const *src,
                    uint8_t         buffer[],
                    size_t          buffer_size,
                    size_t         *offset) = RESOLVE_SYS(Tss2_MU_TPM2B_PUBLIC_Marshal);
    return ptr(src, buffer, buffer_size, offset);
}

TSS2_RC
Tss2_MU_TPMT_SIGNATURE_Marshal(
    TPMT_SIGNATURE const *src,
    uint8_t         buffer[],
    size_t          buffer_size,
    size_t         *offset) {
    
    TSS2_RC (*ptr)(TPMT_SIGNATURE const *src,
                    uint8_t         buffer[],
                    size_t          buffer_size,
                    size_t         *offset) = RESOLVE_MU(Tss2_MU_TPMT_SIGNATURE_Marshal);
    return ptr(src, buffer, buffer_size, offset);
}

TSS2_RC
Tss2_MU_TPM2B_PRIVATE_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_PRIVATE  *dest) {
    TSS2_RC (*ptr)(uint8_t const   buffer[],
                    size_t          buffer_size,
                    size_t         *offset,
                    TPM2B_PRIVATE  *dest) = RESOLVE_MU(Tss2_MU_TPM2B_PRIVATE_Unmarshal);
    return ptr(buffer, buffer_size, offset, dest);
}

TSS2_RC
Tss2_MU_TPM2B_PUBLIC_Unmarshal(
    uint8_t const   buffer[],
    size_t          buffer_size,
    size_t         *offset,
    TPM2B_PUBLIC  *dest) {
    TSS2_RC (*ptr)(uint8_t const   buffer[],
                    size_t          buffer_size,
                    size_t         *offset,
                    TPM2B_PUBLIC  *dest) = RESOLVE_MU(Tss2_MU_TPM2B_PUBLIC_Unmarshal);
    return ptr(buffer, buffer_size, offset, dest);
}
