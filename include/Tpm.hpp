//
//  Tpm.hpp
//  lib-cpp-tpm
//
//  Created by David C Zech on 10/23/18.
//  Copyright © 2018 David C Zech. All rights reserved.
//

#ifndef Tpm_hpp
#define Tpm_hpp
#include <memory>
#include <vector>
#include <tss2/tss2_sys.h>

namespace Tpm {
    typedef enum Version {
        V1_2,
        V2_0,
        NONE
    } Verison;
    
    typedef enum Usage {
        BINDING,
        SIGNING
    } Usage;
    
    struct Key {
        
    };
    
    class Base {
    public:
        virtual std::unique_ptr<Key> createKey(Usage type, const std::vector<uint8_t>& keyAuth, const std::vector<uint8_t>& aikAuth);
        virtual ~Base() = 0;
    };
    std::unique_ptr<Tpm::Base> open(const char* config = nullptr, bool simulator = false);
    
    namespace Linux {
        class V1_2 : public Tpm::Base {
        public:
            V1_2(const char* config = nullptr, bool simulator = false);
            virtual std::unique_ptr<Tpm::Key> createKey(Usage type, const std::vector<uint8_t>& keyAuth, const std::vector<uint8_t>& aikAuth);
            virtual ~V1_2();
        };
        class V2_0 : public Tpm::Base {
            void* tctiLib;
            TSS2_TCTI_CONTEXT* tcti;
            void* sapiLib;
            TSS2_SYS_CONTEXT* sapi;
        public:
            V2_0(const char* config = nullptr, bool simulator = false);
            virtual std::unique_ptr<Tpm::Key> createKey(Usage type, const std::vector<uint8_t>& keyAuth, const std::vector<uint8_t>& aikAuth);
            virtual ~V2_0();
        };
    }
}

#endif /* Tpm_hpp */
