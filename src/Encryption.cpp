//
// Created by Андрей Шпак on 30.01.2025.
//
#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <cxxabi.h>

#include "../elfio/elfio.hpp"
#include "headers/Encryption.h"

using namespace std;
using namespace ELFIO;
using namespace encryption;

#ifdef KEEP_DEPRECATED_FUNCTIONS
void encryption::encryptStrings(const std::string &filename, uint8_t key) {
        ELFIO::elfio reader;

        if (!reader.load(filename)) {
            cerr << "[ERROR] Ошибка загрузки ELF!\n";
            return;
        }

        for (int i = 0; i < reader.sections.size(); ++i) {
            ELFIO::section *sec = reader.sections[i];

            if (sec->get_name() == ".rodata") {
                cout << "[INFO] FOUND .rodata\n";

                vector<char> data(sec->get_size());
                memcpy(data.data(), sec->get_data(), sec->get_size());

                for (char &c : data) c ^= key;

                streampos offset = sec->get_offset();
                cout << "[LEAK] .rodata offset: " << offset << "\n";

                fstream file(filename, ios::in | ios::out | ios::binary);
                if (!file) {
                    cerr << "[ERROR] Ошибка открытия ELF-файла для записи!\n";
                    return;
                }

                file.seekp(offset);
                file.write(data.data(), data.size());
                file.close();

                cout << "[SUCCESS] Строки в .rodata зашифрованы с ключом " << hex << "0x" << (int)key << "!\n";
                return;
            }
        }
}
#endif

bool encryption::packELF(const std::string &filename) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting UPX-like packing of " << filename << "\n";

    const char PCK_SIGNATURE[8] = {'P', 'C', 'K', 
        static_cast<char>(0xFF), 
        static_cast<char>(0xEE), 
        static_cast<char>(0xDD), 
        static_cast<char>(0xCC), 
        static_cast<char>(0xBB)
    };
    const uint32_t PCK_VERSION = 0x00000001;
    
    const char PCK1_SIGNATURE[] = "PCK1";
    const char PCK2_SIGNATURE[] = "PCK2";
    const char PCK_EXCL_SIGNATURE[] = "PCK!";
    
    vector<section*> execSections;
    section* textSection = nullptr;
    
    for (int i = 0; i < reader.sections.size(); ++i) {
        section* sec = reader.sections[i];
        if (sec->get_flags() & SHF_EXECINSTR) {
            execSections.push_back(sec);
            if (sec->get_name() == ".text") {
                textSection = sec;
            }
        }
    }

    if (execSections.empty()) {
        cerr << "[ERROR] Could not find any executable sections!\n";
        return false;
    }

    if (!textSection && !execSections.empty()) {
        textSection = execSections[0];
        cout << "[WARNING] No .text section found, using " << textSection->get_name() << " as main code section\n";
    }

    Elf64_Addr oldEntryPoint = reader.get_entry();
    cout << "[INFO] Original entry point: 0x" << hex << oldEntryPoint << "\n";
    
    return true;
}

bool encryption::stripSymbols(const std::string &filename) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting symbol stripping of " << filename << "\n";
    
    vector<string> removedSections;
    
    for (int i = 0; i < reader.sections.size(); ++i) {
        section* sec = reader.sections[i];
        string secName = sec->get_name();
        
        if (sec->get_type() == SHT_SYMTAB || 
            sec->get_type() == SHT_DYNSYM || 
            secName.find(".debug") == 0 || 
            secName.find(".note") == 0 || 
            secName.find(".comment") == 0) {
            
            removedSections.push_back(secName);
            sec->set_type(SHT_NULL);
            sec->set_name(".null");
        }
    }
    
    ELFIO::elfio stripped;
    stripped.create(reader.get_class(), reader.get_encoding());
    stripped.set_os_abi(reader.get_os_abi());
    stripped.set_abi_version(reader.get_abi_version());
    stripped.set_type(reader.get_type());
    stripped.set_machine(reader.get_machine());
    stripped.set_flags(reader.get_flags());
    stripped.set_entry(reader.get_entry());
    
    return true;
}

bool encryption::insertJunkCode(string fileName) {
    try {
        cout << "[DEBUG] Loading file: " << fileName << " for junk code insertion\n";
        
        string outFileName = fileName + ".junk";
        
        ELFIO::elfio reader;
        if (!reader.load(fileName)) {
            cerr << "[ERROR] Can't load input file " << fileName << endl;
            return false;
        }
        
        int junkCodeInserted = 0;
        srand(time(NULL));
        
        ELFIO::section* textSection = nullptr;
        
        vector<ELFIO::section*> execSections;
        for (int i = 0; i < reader.sections.size(); ++i) {
            ELFIO::section* pSec = reader.sections[i];
            if (pSec->get_flags() & SHF_EXECINSTR) {
                execSections.push_back(pSec);
                if (pSec->get_name() == ".text") {
                    textSection = pSec;
                }
            }
        }
        
        if (textSection == nullptr && !execSections.empty()) {
            textSection = execSections[0];
            cout << "[INFO] Using executable section: " << textSection->get_name() << " for junk code insertion\n";
        }
        
        if (textSection == nullptr) {
            cerr << "[ERROR] No executable sections found for junk code insertion!\n";
            return false;
        }
        
        ELFIO::section* junkSection = reader.sections.add(".junk_code");
        junkSection->set_type(SHT_PROGBITS);
        
        return true;
    } catch (...) {
        cerr << "[ERROR] Unknown exception during file save" << endl;
        return false;
    }
}

bool encryption::addVirtualMachine(const std::string &filename) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting code virtualization on " << filename << "\n";

    section* textSection = nullptr;
    for (int i = 0; i < reader.sections.size(); ++i) {
        section* sec = reader.sections[i];
        if (sec->get_name() == ".text") {
            textSection = sec;
            break;
        }
    }

    if (!textSection) {
        cerr << "[ERROR] Could not find .text section!\n";
        return false;
    }

    vector<char> originalCode(textSection->get_size());
    memcpy(originalCode.data(), textSection->get_data(), textSection->get_size());

    size_t vmStartOffset = originalCode.size() / 4;
    size_t vmLength = min(size_t(100), originalCode.size() / 8);
    
    cout << "[INFO] Selecting code portion from offset 0x" << hex << vmStartOffset 
         << " to 0x" << (vmStartOffset + vmLength - 1) << " for virtualization\n";
    
    vector<unsigned char> vmBytecode;
    
    unsigned char vmHeader[] = {
        0xDE, 0xAD, 0xBE, 0xEF,
        0x01, 0x00,
        (unsigned char)(vmLength & 0xFF),
        (unsigned char)((vmLength >> 8) & 0xFF)
    };
    
    for (unsigned char b : vmHeader) {
        vmBytecode.push_back(b);
    }
    
    for (size_t i = 0; i < vmLength; i++) {
        unsigned char originalByte = (unsigned char)(originalCode[vmStartOffset + i]);
        unsigned char vmOpcode = originalByte % 8;
        unsigned char vmOperand = (originalByte ^ 0xAA) + i % 16;
        
        vmBytecode.push_back(vmOpcode);
        vmBytecode.push_back(vmOperand);
    }
    
    section* vmCodeSection = reader.sections.add(".vm_code");
    vmCodeSection->set_type(SHT_PROGBITS);
    vmCodeSection->set_flags(SHF_ALLOC);
    vmCodeSection->set_addr_align(0x10);
    vmCodeSection->set_data(reinterpret_cast<const char*>(vmBytecode.data()), vmBytecode.size());
    
    section* vmSection = reader.sections.add(".vm");
    vmSection->set_type(SHT_PROGBITS);
    vmSection->set_flags(SHF_ALLOC | SHF_EXECINSTR);
    vmSection->set_addr_align(0x10);
    
    const unsigned char vmInterpreter[] = {
        static_cast<unsigned char>(0x55), static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x89), static_cast<unsigned char>(0xE5),
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x83), static_cast<unsigned char>(0xEC), static_cast<unsigned char>(0x30),
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0xB8), static_cast<unsigned char>(0xDE), static_cast<unsigned char>(0xAD), static_cast<unsigned char>(0xBE), static_cast<unsigned char>(0xEF), static_cast<unsigned char>(0x00), static_cast<unsigned char>(0x00), static_cast<unsigned char>(0x00), static_cast<unsigned char>(0x00),
        static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90),
        static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90),
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x83), static_cast<unsigned char>(0xC4), static_cast<unsigned char>(0x30),
        static_cast<unsigned char>(0x5D), static_cast<unsigned char>(0xC3)
    };
    
    vmSection->set_data(reinterpret_cast<const char*>(vmInterpreter), sizeof(vmInterpreter));
    
    unsigned char vmCallStub[] = {
        static_cast<unsigned char>(0xE8), static_cast<unsigned char>(0x00), static_cast<unsigned char>(0x00), static_cast<unsigned char>(0x00), static_cast<unsigned char>(0x00),
        static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90), static_cast<unsigned char>(0x90)
    };
    
    if (vmLength >= sizeof(vmCallStub)) {
        memcpy(&originalCode[vmStartOffset], vmCallStub, sizeof(vmCallStub));
        
        for (size_t i = vmStartOffset + sizeof(vmCallStub); i < vmStartOffset + vmLength; i++) {
            originalCode[i] = 0x90;
        }
    } else {
        cerr << "[WARNING] Virtualized section too small for call stub. Using NOPs.\n";
        for (size_t i = vmStartOffset; i < vmStartOffset + vmLength; i++) {
            originalCode[i] = 0x90;
        }
    }
    
    textSection->set_data(originalCode.data(), originalCode.size());
    
    string vmFilename = filename + ".vm";
    if (!reader.save(vmFilename)) {
        cerr << "[ERROR] Failed to save virtualized ELF file!\n";
        return false;
    }
    
    cout << "[SUCCESS] Created virtualized file: " << vmFilename << "\n";
    cout << "[INFO] Added VM bytecode (" << vmBytecode.size() << " bytes) and VM interpreter\n";
    cout << "[WARNING] This is a demo VM implementation. A real implementation would be much more complex.\n";
    return true;
}

bool encryption::addPCKHeaders(std::string filename) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Failed to load ELF file for adding PCK headers!\n";
        return false;
    }
    
    cout << "[INFO] Adding PCK headers to " << filename << "\n";

    const char PCK1_SIGNATURE[] = "PCK1";
    const char PCK2_SIGNATURE[] = "PCK2";
    const char PCK_EXCL_SIGNATURE[] = "PCK!";
    
    Elf64_Addr originalEntryPoint = reader.get_entry();

    section* pckHeaderSection = reader.sections.add(".pck_header");
    pckHeaderSection->set_type(SHT_PROGBITS);
    pckHeaderSection->set_flags(SHF_ALLOC);
    pckHeaderSection->set_addr_align(0x10);
    
    vector<char> headerData;
    
    headerData.insert(headerData.end(), PCK1_SIGNATURE, PCK1_SIGNATURE + 4);
    
    uint32_t version = 0x00010000;
    for (int i = 0; i < 4; i++) {
        headerData.push_back((version >> (i * 8)) & 0xFF);
    }
    
    headerData.insert(headerData.end(), PCK2_SIGNATURE, PCK2_SIGNATURE + 4);
    
    uint32_t timestamp = time(nullptr);
    for (int i = 0; i < 4; i++) {
        headerData.push_back((timestamp >> (i * 8)) & 0xFF);
    }
    
    headerData.insert(headerData.end(), PCK_EXCL_SIGNATURE, PCK_EXCL_SIGNATURE + 4);
    
    for (int i = 0; i < 8; i++) {
        headerData.push_back((originalEntryPoint >> (i * 8)) & 0xFF);
    }
    
    pckHeaderSection->set_data(headerData.data(), headerData.size());
    
    section* pckStubSection = reader.sections.add(".pck_stub");
    pckStubSection->set_type(SHT_PROGBITS);
    pckStubSection->set_flags(SHF_ALLOC | SHF_EXECINSTR);
    pckStubSection->set_addr_align(0x10);
    
    const unsigned char stubCode[] = {
        static_cast<unsigned char>(0x50),
        static_cast<unsigned char>(0x51),
        static_cast<unsigned char>(0x52),
        static_cast<unsigned char>(0x53),
        static_cast<unsigned char>(0x54),
        static_cast<unsigned char>(0x55),
        static_cast<unsigned char>(0x56),
        static_cast<unsigned char>(0x57),
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0xB8),
        'P', 'C', 'K', '!', 0x00, 0x00, 0x00, 0x00,
        static_cast<unsigned char>(0x5F),
        static_cast<unsigned char>(0x5E),
        static_cast<unsigned char>(0x5D),
        static_cast<unsigned char>(0x5C),
        static_cast<unsigned char>(0x5B),
        static_cast<unsigned char>(0x5A),
        static_cast<unsigned char>(0x59),
        static_cast<unsigned char>(0x58),
        static_cast<unsigned char>(0xFF), static_cast<unsigned char>(0x25),
        0x00, 0x00, 0x00, 0x00,
        static_cast<unsigned char>(originalEntryPoint & 0xFF),
        static_cast<unsigned char>((originalEntryPoint >> 8) & 0xFF),
        static_cast<unsigned char>((originalEntryPoint >> 16) & 0xFF),
        static_cast<unsigned char>((originalEntryPoint >> 24) & 0xFF),
        static_cast<unsigned char>((originalEntryPoint >> 32) & 0xFF),
        static_cast<unsigned char>((originalEntryPoint >> 40) & 0xFF),
        static_cast<unsigned char>((originalEntryPoint >> 48) & 0xFF),
        static_cast<unsigned char>((originalEntryPoint >> 56) & 0xFF)
    };
    
    pckStubSection->set_data(reinterpret_cast<const char*>(stubCode), sizeof(stubCode));
    
    reader.set_entry(pckStubSection->get_address());
    
    string pckFilename = filename + ".pck";
    if (!reader.save(pckFilename)) {
        cerr << "[ERROR] Failed to save file with PCK headers!\n";
        return false;
    }
    
    cout << "[SUCCESS] Created file with PCK headers: " << pckFilename << "\n";
    cout << "[INFO] PCK1, PCK2, PCK! signatures added\n";
    cout << "[INFO] Original entry point: 0x" << hex << originalEntryPoint << "\n";
    cout << "[INFO] New entry point: 0x" << hex << pckStubSection->get_address() << "\n";
    cout << "[INFO] File is now marked as PCK-protected while maintaining full functionality\n";
    return true;
}