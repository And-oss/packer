#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>

#include "elfio/elfio.hpp"
#include "keystone/keystone.h"

using namespace std;ar


// [BUILD] g++ packer.cpp -o packer -lkeystone

void encryptStrings(const std::string &filename, uint8_t key) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        std::cerr << "[ERROR] Ошибка загрузки ELF!\n";
        return;
    }

    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section *sec = reader.sections[i];

        if (sec->get_name() == ".rodata") {
            std::cout << "[INFO] FOUND .rodata\n";

            std::vector<char> data(sec->get_size());
            memcpy(data.data(), sec->get_data(), sec->get_size());

            for (char &c : data) c ^= key;

            std::streampos offset = sec->get_offset();
            std::cout << "[LEAK] .rodata offset: " << offset << "\n";

            std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
            if (!file) {
                std::cerr << "[ERROR] Ошибка открытия ELF-файла для записи!\n";
                return;
            }

            file.seekp(offset);
            file.write(data.data(), data.size());
            file.close();

            std::cout << "[SUCCESS] Строки в .rodata зашифрованы с ключом " << std::hex << "0x" << (int)key << "!\n";
            return;
        }
    }

    std::cerr << "[ERROR] Секция .rodata не найдена!\n";
}

int NOPInjectionELF(const std::string &filename, int count_nops = 10, uint64_t target_addr = 0, bool patch_end = false) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        std::cerr << "[ERROR] Couldn't open file " << filename << "\n";
        return -1;
    }

    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section *sec = reader.sections[i];

        if (sec->get_name() == ".text") {
            std::cout << "[INFO] FOUND .text section\n";

            std::vector<char> data(sec->get_size());
            memcpy(data.data(), sec->get_data(), sec->get_size());

            std::streampos offset = sec->get_offset();
            uint64_t text_vaddr = sec->get_address();

            if (patch_end) {
                std::cout << "[MODIFY] Overwriting last " << count_nops << " bytes of .text with NOPs\n";
                for (int i = sec->get_size() - count_nops; i < sec->get_size(); ++i) {
                    data[i] = '\x90';
                }
            } else if (target_addr != 0) {
                uint64_t patch_offset = target_addr - text_vaddr;
                if (patch_offset >= sec->get_size()) {
                    std::cerr << "[ERROR] Target address is outside .text section!\n";
                    return -1;
                }

                std::cout << "[MODIFY] Injecting " << count_nops << " NOPs at address 0x"
                          << std::hex << target_addr << " (offset: 0x" << patch_offset << ")\n";

                for (int i = 0; i < count_nops && (patch_offset + i) < sec->get_size(); ++i) {
                    data[patch_offset + i] = '\x90';
                }
            } else {
                std::cout << "[MODIFY] Injecting " << count_nops << " NOPs at start of .text\n";
                for (int i = 0; i < count_nops && i < data.size(); ++i) {
                    data[i] = '\x90';
                }
            }

            std::fstream file(filename, std::ios::in | std::ios::out | std::ios::binary);
            if (!file) {
                std::cerr << "[ERROR] Couldn't open ELF file for writing!\n";
                return -1;
            }

            file.seekp(offset);
            file.write(data.data(), data.size());
            file.close();

            std::cout << "[SUCCESS] Modified .text section!\n";
            return 0;
        }
    }

    std::cerr << "[ERROR] .text section not found!\n";
    return -1;
}


void printHelp() {
    std::cout << "Usage:\n"
              << "  -f <filename>   Specify ELF file to modify\n"
              << "  -ni             Inject NOPs into .text section\n"
              << "  -s              Encrypt strings in .rodata\n"
              << "  -k <key>        Set XOR key for string encryption (default: 0xAA)\n"
              << "  -h              Show this help message\n";
}
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printHelp();
        return 1;
    }

    std::string filename;
    bool nopInjection = false;
    bool stringObfuscation = false;
    uint8_t xorKey = 0xAA; // Default XOR key
    uint64_t targetAddr = 0;
    bool patchEnd = false;
    int nopCount = 10;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h") {
            printHelp();
            return 0;
        } else if (arg == "-ni") {
            nopInjection = true;
        } else if (arg == "-s") {
            stringObfuscation = true;
        } else if (arg == "-f") {
            if (i + 1 < argc) {
                filename = argv[++i];
            } else {
                std::cerr << "[ERROR] Missing filename after -f\n";
                return 1;
            }
        } else if (arg == "-k") {
            if (i + 1 < argc) {
                std::stringstream ss(argv[++i]);
                int tempKey;
                ss >> std::hex >> tempKey;
                if (ss.fail() || tempKey < 0 || tempKey > 255) {
                    std::cerr << "[ERROR] Invalid key! Must be a number (0-255) or hex (0x00-0xFF).\n";
                    return 1;
                }
                xorKey = static_cast<uint8_t>(tempKey);
            } else {
                std::cerr << "[ERROR] Missing key after -k\n";
                return 1;
            }
        } else if (arg == "-addr") {
            if (i + 1 < argc) {
                std::stringstream ss(argv[++i]);
                ss >> std::hex >> targetAddr;
                if (ss.fail()) {
                    std::cerr << "[ERROR] Invalid address format!\n";
                    return 1;
                }
            } else {
                std::cerr << "[ERROR] Missing address after -addr\n";
                return 1;
            }
        } else if (arg == "-end") {
            patchEnd = true;
        }
    }

    if (filename.empty()) {
        std::cerr << "[ERROR] No filename specified!\n";
        return 1;
    }

    if (nopInjection) {
        NOPInjectionELF(filename, nopCount, targetAddr, patchEnd);
    }

    if (stringObfuscation) {
        encryptStrings(filename, xorKey);
    }

    return 0;
}