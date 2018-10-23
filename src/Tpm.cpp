//
//  Tpm.cpp
//  lib-cpp-tpm
//
//  Created by David C Zech on 10/23/18.
//  Copyright © 2018 David C Zech. All rights reserved.
//

#include <Tpm.hpp>
#include <fstream>
#include <string>

bool checkSysClassTpm12() {
    std::ifstream f("/sys/class/tpm/tpm0/device/caps");
    if (f) {
        std::string line;
        if(std::getline(f, line) && line.find("1.2") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool checkSysClassTpm20() {
    std::ifstream f("/sys/class/tpm/tpm0/device/description");
    if (f) {
        std::string line;
        if(std::getline(f, line) && line.find("2.0") != std::string::npos) {
            return true;
        }
    }
    return false;
}

Tpm::Version detectTpmVersion() {
    if (checkSysClassTpm12()) {
        return Tpm::Version::V1_2;
    } else if (checkSysClassTpm20()) {
        return Tpm::Version::V2_0;
    }
    return Tpm::Version::NONE;
}

std::unique_ptr<Tpm::Base> open(const char* config, bool simulator) {
    switch (detectTpmVersion()) {
        case Tpm::Verison::V1_2:
            return std::make_unique<Tpm::Linux::V1_2>(config, simulator);
        case Tpm::Version::V2_0:
            return std::make_unique<Tpm::Linux::V2_0>(config, simulator);
        case Tpm::Version::NONE:
            return nullptr;
    }
}
