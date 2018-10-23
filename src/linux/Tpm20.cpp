//
//  Tpm20.cpp
//  lib-cpp-tpm
//
//  Created by David C Zech on 10/23/18.
//  Copyright © 2018 David C Zech. All rights reserved.
//

#include <Tpm.hpp>
#include <dlfcn.h>
#include <tss2/tss2_sys.h>

Tpm::Linux::V2_0::V2_0(const char* config, bool simulator) {
    const char* tctiName = simulator ? "libtcti-socket.so" : "libtcti-tabrmd.so";
    tctiLib = dlopen(tctiName, RTLD_LAZY);
    if (!tctiLib) {
        throw "Could not dlopen tcti library";
    }
    
    TSS2_TCTI_INFO_FUNC infoFn = reinterpret_cast<TSS2_TCTI_INFO_FUNC>(dlsym(tctiLib, TSS2_TCTI_INFO_SYMBOL));
    if (!infoFn) {
        throw "Could not resolve TSS2_TCTI_INFO_SYMBOL";
    }
    
    auto info = infoFn();
    size_t size;
    TPM2_RC rc = info->init(nullptr, &size, config);
    if (rc != TPM2_RC_SUCCESS) {
        dlclose(tctiLib);
        throw "tcti info init failed";
    }
    
    tcti = reinterpret_cast<TSS2_TCTI_CONTEXT*>(calloc(1, size));
    if (!tcti) {
        throw "Out of memory";
    }
    
    rc = info->init(tcti, &size, config);
    if (rc != TPM2_RC_SUCCESS) {
        throw "tcti info init failed";
    }
    
    size = Tss2_Sys_GetContextSize(0);
    sapi = reinterpret_cast<TSS2_SYS_CONTEXT*>(calloc(1, size));
    if (!sapi) {
        throw "Out of memory";
    }
    rc = Tss2_Sys_Initialize(sapi, size, tcti, nullptr); // TODO set ABI VERISON
    if (rc != TPM2_RC_SUCCESS) {
        throw "Tss2_Sys_Initialize failed";
    }
}

std::unique_ptr<Tpm::Key> Tpm::Linux::V2_0::createKey(Tpm::Usage type, const std::vector<uint8_t>& keyAuth, const std::vector<uint8_t>& aikAuth) {
    throw 1;
}

Tpm::Linux::V2_0::~V2_0() {
    if (tctiLib) {
        dlclose(tctiLib);
    }
    if (tcti) {
        free(tcti);
    }
    if (sapiLib) {
        dlclose(sapiLib);
    }
    if (sapi) {
        free(sapi);
    }
}
