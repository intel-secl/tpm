//
//  tss.cpp
//  Trampoline stus for tss 1.2 functions
//
//  Created by David C Zech on 11/6/18.
//  Copyright © 2018 Intel. All rights reserved.
//

#include "tpm.h"
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <dlfcn.h>
#include <stdio.h>
#include "util.h"

void* getLibTspi() {
    static void* libtspi = NULL;
    if (libtspi == NULL) {
        libtspi = dlopen(LIB_TSPI, RTLD_LAZY);
    }
    return libtspi;
}

#define RESOLVE(symbol) resolve(getLibTspi(), #symbol )

TSS_RESULT Tspi_Context_Create(TSS_HCONTEXT* context) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT*) = (TSS_RESULT (*)(TSS_HCONTEXT*)) RESOLVE(Tspi_Context_Create);
    return ptr(context);
}

TSS_RESULT Tspi_Context_Connect(TSS_HCONTEXT hContext, TSS_UNICODE* wszDestination) { 
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_UNICODE*) = RESOLVE(Tspi_Context_Connect);
    return ptr(hContext, wszDestination);
}

TSS_RESULT Tspi_Context_GetDefaultPolicy(TSS_HCONTEXT hContext, TSS_HPOLICY *phPolicy) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_HPOLICY*) = RESOLVE(Tspi_Context_GetDefaultPolicy);
    return ptr(hContext, phPolicy);
}

TSS_RESULT Tspi_Context_GetTpmObject(TSS_HCONTEXT tspContext, TSS_HTPM * phTPM) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_HTPM*) = (TSS_RESULT (*)(TSS_HCONTEXT, TSS_HTPM*))RESOLVE(Tspi_Context_GetTpmObject);
    return ptr(tspContext, phTPM);
}

TSS_RESULT Tspi_Context_CloseObject(TSS_HCONTEXT tspContext, TSS_HOBJECT hObject) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_HOBJECT) = (TSS_RESULT (*)(TSS_HCONTEXT, TSS_HOBJECT))RESOLVE(Tspi_Context_CloseObject);
    return ptr(tspContext, hObject);
}

TSS_RESULT Tspi_Context_Close(TSS_HCONTEXT tspContext) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT) = (TSS_RESULT (*)(TSS_HCONTEXT))RESOLVE(Tspi_Context_Close);
    return ptr(tspContext);
}

TSS_RESULT Tspi_Context_CreateObject(TSS_HCONTEXT hContext, TSS_FLAG objectType, TSS_FLAG initFlags, TSS_HOBJECT *phObject) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_FLAG, TSS_FLAG, TSS_HOBJECT*) = (TSS_RESULT (*)(TSS_HCONTEXT, TSS_FLAG, TSS_FLAG, TSS_HOBJECT*))RESOLVE(Tspi_Context_CreateObject);
    return ptr(hContext, objectType, initFlags, phObject);
}

TSS_RESULT Tspi_Context_LoadKeyByUUID(TSS_HCONTEXT hContext, TSS_FLAG persistentStorageType, TSS_UUID uuidData, TSS_HKEY *phKey) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_FLAG, TSS_UUID, TSS_HKEY*) = (TSS_RESULT (*)(TSS_HCONTEXT, TSS_FLAG, TSS_UUID, TSS_HKEY*))RESOLVE(Tspi_Context_LoadKeyByUUID);
    return ptr(hContext, persistentStorageType, uuidData, phKey);
}

TSS_RESULT Tspi_Policy_SetSecret(TSS_HPOLICY hPolicy, TSS_FLAG secretMode, UINT32 ulSecretLength, BYTE *rgbSecret) {
    TSS_RESULT (*ptr)(TSS_HPOLICY, TSS_FLAG, UINT32, BYTE*) = (TSS_RESULT (*)(TSS_HPOLICY, TSS_FLAG, UINT32, BYTE*))RESOLVE(Tspi_Policy_SetSecret);
    return ptr(hPolicy, secretMode, ulSecretLength, rgbSecret);
}

TSS_RESULT Tspi_Policy_AssignToObject(TSS_HPOLICY hPolicy, TSS_HOBJECT hObject) {
    TSS_RESULT (*ptr)(TSS_HPOLICY, TSS_HOBJECT) = RESOLVE(Tspi_Policy_AssignToObject);
    return ptr(hPolicy, hObject);
}

TSS_RESULT Tspi_Context_FreeMemory(TSS_HCONTEXT hContext, BYTE *rgbMemory) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, BYTE*) = RESOLVE(Tspi_Context_FreeMemory);
    return ptr(hContext, rgbMemory);
}

TSS_RESULT Tspi_Key_CreateKey(TSS_HKEY hKey, TSS_HKEY hWrappingKey, TSS_HPCRS hPcrComposite) {
    TSS_RESULT (*ptr)(TSS_HKEY, TSS_HKEY, TSS_HPCRS) = RESOLVE(Tspi_Key_CreateKey);
    return ptr(hKey, hWrappingKey, hPcrComposite);
}

TSS_RESULT Tspi_GetAttribData(TSS_HOBJECT hObject, TSS_FLAG attribFlag, TSS_FLAG subFlag, UINT32 *pulAttribDataSize, BYTE **prgbAttribData) {
    TSS_RESULT (*ptr)(TSS_HOBJECT, TSS_FLAG, TSS_FLAG, UINT32*, BYTE**) = RESOLVE(Tspi_GetAttribData);
    return ptr(hObject, attribFlag, subFlag, pulAttribDataSize, prgbAttribData);
}

TSS_RESULT Tspi_Key_LoadKey(TSS_HKEY hKey, TSS_HKEY hUnwrappingKey) {
    TSS_RESULT (*ptr)(TSS_HKEY, TSS_HKEY) = RESOLVE(Tspi_Key_LoadKey);
    return ptr(hKey, hUnwrappingKey);
}

TSS_RESULT Tspi_Context_GetKeyByUUID(TSS_HCONTEXT hContext, TSS_FLAG persistentStorageType, TSS_UUID uuidData, TSS_HKEY *phKey) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_FLAG, TSS_UUID, TSS_HKEY*) = RESOLVE(Tspi_Context_GetKeyByUUID);
    return ptr(hContext, persistentStorageType, uuidData, phKey);
}

TSS_RESULT Tspi_TPM_GetRandom(TSS_HTPM hTpm, UINT32 ulRandomDataLength, BYTE **prgbRandomData) {
    TSS_RESULT (*ptr)(TSS_HTPM, UINT32, BYTE**) = RESOLVE(Tspi_TPM_GetRandom);
    return ptr(hTpm, ulRandomDataLength, prgbRandomData);
}

TSS_RESULT Tspi_Key_CertifyKey(TSS_HKEY hKey, TSS_HKEY hCertifyingKey, TSS_VALIDATION *pValidationData) {
    TSS_RESULT (*ptr)(TSS_HKEY, TSS_HKEY, TSS_VALIDATION*) = RESOLVE(Tspi_Key_CertifyKey);
    return ptr(hKey, hCertifyingKey, pValidationData);
}

// BYTE* Trspi_Native_To_UNICODE(BYTE *string, unsigned int *len) {
//     return CALL(Trspi_Native_To_UNICODE, string, len);
// }

TSS_RESULT Tspi_Context_LoadKeyByBlob(TSS_HCONTEXT hObject, TSS_HKEY hUnwrappingKey, UINT32 ulBlobLength, BYTE *rgbBlobData, TSS_HKEY *phKey) {
    TSS_RESULT (*ptr)(TSS_HCONTEXT, TSS_HKEY, UINT32, BYTE*, TSS_HKEY*) = RESOLVE(Tspi_Context_LoadKeyByBlob);
    return ptr(hObject, hUnwrappingKey, ulBlobLength, rgbBlobData, phKey);
}

TSS_RESULT Tspi_SetAttribData(TSS_HOBJECT hObject, TSS_FLAG attribFlag, TSS_FLAG subFlag, UINT32 ulAttribDataSize, BYTE *rgbAttribData) {
    TSS_RESULT (*ptr)(TSS_HOBJECT, TSS_FLAG, TSS_FLAG, UINT32, BYTE*) = RESOLVE(Tspi_SetAttribData);
    return ptr(hObject, attribFlag, subFlag, ulAttribDataSize, rgbAttribData);
}

TSS_RESULT Tspi_Data_Unbind(TSS_HENCDATA hEncData, TSS_HKEY hKey, UINT32 *pulUnboundDataLength, BYTE **prgbUnboundData) {
    TSS_RESULT (*ptr)(TSS_HENCDATA, TSS_HKEY, UINT32*, BYTE**) = RESOLVE(Tspi_Data_Unbind);
    return ptr(hEncData, hKey, pulUnboundDataLength, prgbUnboundData);
}
