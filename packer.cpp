#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>

#include "elfio/elfio.hpp"
#include "keystone/keystone.h"

#include "src/headers/Encryption.h"
#include "src/Encryption.cpp"

using namespace std;


// [BUILD]  g++ packer.cpp -o packer -lkeystone -ldl

int NOPInjectionELF(const string &filename, int count_nops = 10, uint64_t target_addr = 0, bool patch_end = false) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Couldn't open file " << filename << "\n";
        return -1;
    }

    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section *sec = reader.sections[i];

        if (sec->get_name() == ".text") {
            cout << "[INFO] FOUND .text section\n";

            vector<char> data(sec->get_size());
            memcpy(data.data(), sec->get_data(), sec->get_size());

            streampos offset = sec->get_offset();
            uint64_t text_vaddr = sec->get_address();

            if (patch_end) {
                cout << "[MODIFY] Overwriting last " << count_nops << " bytes of .text with NOPs\n";
                for (int i = sec->get_size() - count_nops; i < sec->get_size(); ++i) {
                    data[i] = '\x90';
                }
            } else if (target_addr != 0) {
                uint64_t patch_offset = target_addr - text_vaddr;
                if (patch_offset >= sec->get_size()) {
                    cerr << "[ERROR] Target address is outside .text section!\n";
                    return -1;
                }

                cout << "[MODIFY] Injecting " << count_nops << " NOPs at address 0x"
                          << hex << target_addr << " (offset: 0x" << patch_offset << ")\n";

                for (int i = 0; i < count_nops && (patch_offset + i) < sec->get_size(); ++i) {
                    data[patch_offset + i] = '\x90';
                }
            } else {
                cout << "[MODIFY] Injecting " << count_nops << " NOPs at start of .text\n";
                for (int i = 0; i < count_nops && i < data.size(); ++i) {
                    data[i] = '\x90';
                }
            }

            fstream file(filename, ios::in | ios::out | ios::binary);
            if (!file) {
                cerr << "[ERROR] Couldn't open ELF file for writing!\n";
                return -1;
            }

            file.seekp(offset);
            file.write(data.data(), data.size());
            file.close();

            cout << "[SUCCESS] Modified .text section!\n";
            return 0;
        }
    }

    cerr << "[ERROR] .text section not found!\n";
    return -1;
}

void printHelp() {
    cout << "Usage:\n"
         << "  -f <filename>   Specify ELF file to modify\n"
         << "  -ni             Inject NOPs into .text section\n"
         << "  -s              Encrypt strings in .rodata\n"
         << "  -k <key>        Set XOR key for string encryption (default: 0xAA)\n"
         << "  -addr <address> Set address to inject NOPs (in hexadecimal format)\n"
         << "  -end            Patch NOPs at the end of .text section instead of a specific address\n"
         << "  -n <num>        Set number of NOPs to inject (default: 10)\n"
         << "  -h              Show this help message\n"
         << "  -es             Encrypt section\n"
         << "  -t              Text which will add into function's name\n";
}

int main(int argc, char *argv[]) {
    cout << " ▄▀▀▄▀▀▀▄  ▄▀▀█▄   ▄▀▄▄▄▄   ▄▀▀▄ █  ▄▀▀█▄▄▄▄  ▄▀▀▄▀▀▀▄ \n"
            "█   █   █ ▐ ▄▀ ▀▄ █ █    ▌ █  █ ▄▀ ▐  ▄▀   ▐ █   █   █ \n"
            "▐  █▀▀▀▀    █▄▄▄█ ▐ █      ▐  █▀▄    █▄▄▄▄▄  ▐  █▀▀█▀  \n"
            "   █       ▄▀   █   █        █   █   █    ▌   ▄▀    █  \n"
            " ▄▀       █   ▄▀   ▄▀▄▄▄▄▀ ▄▀   █   ▄▀▄▄▄▄   █     █   \n"
            "█         ▐   ▐   █     ▐  █    ▐   █    ▐   ▐     ▐   \n"
            "▐                 ▐        ▐        ▐                  " << endl;

    if (argc < 2) {
        printHelp();
        return 1;
    }

    string filename;
    bool nopInjection = false;
    bool stringObfuscation = false;
    bool encryptSection = false;
    bool patchEnd = false;

    uint8_t xorKey = 0xAA; // Default XOR key
    int nopCount = 10; // Default NOP count
    uint64_t targetAddr = 0; // Default Target Address
    std::string text = ".text"; // Default Text

    // Обработка аргументов командной строки
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];

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
                cerr << "[ERROR] Missing filename after -f\n";
                return 1;
            }
        } else if (arg == "-k") {
            if (i + 1 < argc) {
                stringstream ss(argv[++i]);
                int tempKey;
                ss >> hex >> tempKey;
                if (ss.fail() || tempKey < 0 || tempKey > 255) {
                    cerr << "[ERROR] Invalid key! Must be a number (0-255) or hex (0x00-0xFF).\n";
                    return 1;
                }
                xorKey = static_cast<uint8_t>(tempKey);
            } else {
                cerr << "[ERROR] Missing key after -k\n";
                return 1;
            }
        } else if (arg == "-addr") {
            if (i + 1 < argc) {
                stringstream ss(argv[++i]);
                ss >> hex >> targetAddr;
                if (ss.fail()) {
                    cerr << "[ERROR] Invalid address format!\n";
                    return 1;
                }
            } else {
                cerr << "[ERROR] Missing address after -addr\n";
                return 1;
            }
        } else if (arg == "-end") {
            patchEnd = true;
        } else if (arg == "-n") {
            if (i + 1 < argc) {
                stringstream ss(argv[++i]);
                ss >> nopCount;
                if (ss.fail() || nopCount <= 0) {
                    cerr << "[ERROR] Invalid NOP count! Must be a positive integer.\n";
                    return 1;
                }
            } else {
                cerr << "[ERROR] Missing number of NOPs after -n\n";
                return 1;
            }
        } else if (arg == "-es") {
            encryptSection = true;
        } else if (arg == "-t") {  // Обработка аргумента -t для добавления текста в имена функций
            if (i + 1 < argc) {
                text = argv[++i]; // Считываем строку, которую нужно добавить в имя функции
            } else {
                cerr << "[ERROR] Missing text after -t\n";
                return 1;
            }
        }
    }

    // Проверка на отсутствие имени файла
    if (filename.empty()) {
        cerr << "[ERROR] No filename specified!\n";
        return 1;
    }

    // Выполнение различных операций в зависимости от флагов
    if (nopInjection) {
        NOPInjectionELF(filename, nopCount, targetAddr, patchEnd);
    }

    if (stringObfuscation) {
        encryption::encryptStrings(filename, xorKey);
    }

    if (encryptSection) {
        encryption::encryptSection(filename, text , xorKey);
    }

    return 0;
}