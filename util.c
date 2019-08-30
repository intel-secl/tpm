/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void panic(const char* symbol) {
    fprintf(stderr, "Failed to resolve symbol %s\n", symbol);
    exit(EXIT_FAILURE);
}

void* resolve(void* lib, const char* symbol) {
    void* fn = dlsym(lib, symbol);
    if (fn == NULL) {
        panic(symbol);
    }
    return fn;
}