#ifndef PACKER_ENCRYPTION_H
#define PACKER_ENCRYPTION_H

#include <string>

namespace encryption {
    void encryptStrings(const std::string &filename, uint8_t key);
}

#endif // PACKER_ENCRYPTION_H