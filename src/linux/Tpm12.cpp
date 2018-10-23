//
//  Tpm12.cpp
//  lib-cpp-tpm
//
//  Created by David C Zech on 10/23/18.
//  Copyright © 2018 David C Zech. All rights reserved.
//

#include <Tpm.hpp>

Tpm::Linux::V1_2::V1_2(const char* config, bool simulator) {
        
}

std::unique_ptr<Tpm::Key> createKey(Tpm::Usage type, const std::vector<uint8_t>& keyAuth, const std::vector<uint8_t>& aikAuth) {
    throw 1;
}

Tpm::Linux::V1_2::~V1_2() {
    
}
