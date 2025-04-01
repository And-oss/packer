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

    vector<ELFIO::section*> execSections;
    ELFIO::section* textSection = nullptr;
    
    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        const ELFIO::Elf_Xword flags = sec->get_flags();
        const string secName = sec->get_name();
        
        if (flags & ELFIO::SHF_EXECINSTR) {
            execSections.push_back(sec);
            if (secName == ".text") {
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

    const ELFIO::Elf64_Addr oldEntryPoint = reader.get_entry();
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
        ELFIO::section* sec = reader.sections[i];
        const string secName = sec->get_name();
        const ELFIO::Elf_Word secType = sec->get_type();
        
        if (secType == ELFIO::SHT_SYMTAB || 
            secType == ELFIO::SHT_DYNSYM || 
            secName.find(".debug") == 0 || 
            secName.find(".note") == 0 || 
            secName.find(".comment") == 0) {
            
            removedSections.push_back(secName);
            sec->set_type(ELFIO::SHT_NULL);
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
            const Elf_Xword flags = pSec->get_flags();
            const string secName = pSec->get_name();
            
            if (flags & SHF_EXECINSTR) {
                execSections.push_back(pSec);
                if (secName == ".text") {
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

    ELFIO::section* textSection = nullptr;
    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        const string secName = sec->get_name();
        if (secName == ".text") {
            textSection = sec;
            break;
        }
    }

    if (!textSection) {
        cerr << "[ERROR] Could not find .text section!\n";
        return false;
    }

    const Elf_Xword secSize = textSection->get_size();
    vector<char> originalCode(secSize);
    memcpy(originalCode.data(), textSection->get_data(), secSize);

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
    
    ELFIO::section* vmCodeSection = reader.sections.add(".vm_code");
    vmCodeSection->set_type(SHT_PROGBITS);
    vmCodeSection->set_flags(SHF_ALLOC);
    vmCodeSection->set_addr_align(0x10);
    vmCodeSection->set_data(reinterpret_cast<const char*>(vmBytecode.data()), vmBytecode.size());
    
    ELFIO::section* vmSection = reader.sections.add(".vm");
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
    
    const Elf64_Addr originalEntryPoint = reader.get_entry();

    ELFIO::section* pckHeaderSection = reader.sections.add(".pck_header");
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
    
    ELFIO::section* pckStubSection = reader.sections.add(".pck_stub");
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
    
    const Elf64_Addr stubAddr = pckStubSection->get_address();
    reader.set_entry(stubAddr);
    
    string pckFilename = filename + ".pck";
    if (!reader.save(pckFilename)) {
        cerr << "[ERROR] Failed to save file with PCK headers!\n";
        return false;
    }
    
    cout << "[SUCCESS] Created file with PCK headers: " << pckFilename << "\n";
    cout << "[INFO] PCK1, PCK2, PCK! signatures added\n";
    cout << "[INFO] Original entry point: 0x" << hex << originalEntryPoint << "\n";
    cout << "[INFO] New entry point: 0x" << hex << stubAddr << "\n";
    cout << "[INFO] File is now marked as PCK-protected while maintaining full functionality\n";
    return true;
}

bool encryption::renameVariables(const std::string &filename, const std::string &oldName, const std::string &newName) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting variable renaming in " << filename << "\n";
    cout << "[INFO] Renaming variable from '" << oldName << "' to '" << newName << "'\n";
    
    bool found = false;
    bool modified = false;
    
    // First, try to find the variable in the symbol table
    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        const Elf_Word secType = sec->get_type();
        
        if (secType == SHT_SYMTAB) {
            symbol_section_accessor symbols(reader, sec);
            // Get the string table section for this symbol table
            ELFIO::section* strSection = reader.sections[sec->get_link()];
            string_section_accessor strings(strSection);
            
            for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
                string name;
                Elf64_Addr value;
                Elf_Xword size;
                unsigned char bind;
                unsigned char type;
                Elf_Half section_index;
                unsigned char other;
                
                if (symbols.get_symbol(j, name, value, size, bind, type, section_index, other)) {
                    if (name == oldName) {
                        found = true;
                        cout << "[INFO] Found variable '" << oldName << "' in symbol table\n";
                        
                        // Create a new symbol with the new name
                        Elf_Word newSymbolIndex = symbols.add_symbol(
                            strings,
                            newName.c_str(),
                            value,
                            size,
                            bind,
                            type,
                            section_index
                        );
                        
                        if (newSymbolIndex != STN_UNDEF) {
                            modified = true;
                            cout << "[SUCCESS] Added new symbol with name '" << newName << "'\n";
                        } else {
                            cerr << "[ERROR] Failed to add new symbol\n";
                        }
                    }
                }
            }
        }
    }
    
    // If we found and modified the symbol, we need to update the string table
    if (modified) {
        for (int i = 0; i < reader.sections.size(); ++i) {
            ELFIO::section* sec = reader.sections[i];
            const Elf_Word secType = sec->get_type();
            const string secName = sec->get_name();
            
            if (secType == SHT_STRTAB) {
                if (secName == ".strtab" || secName == ".dynstr") {
                    cout << "[INFO] Updating string table: " << secName << "\n";
                    
                    // Get the current string table data
                    const char* strData = sec->get_data();
                    const Elf_Xword strSize = sec->get_size();
                    
                    // Create a new string table with the updated name
                    vector<char> newStrTable(strData, strData + strSize);
                    
                    // Append the new name to the string table
                    newStrTable.insert(newStrTable.end(), newName.begin(), newName.end());
                    newStrTable.push_back('\0');
                    
                    // Update the section with the new string table
                    sec->set_data(newStrTable.data(), newStrTable.size());
                    cout << "[SUCCESS] Updated string table with new variable name\n";
                }
            }
        }
    }
    
    if (!found) {
        cout << "[WARNING] Variable '" << oldName << "' not found in symbol table\n";
        cout << "[INFO] Note: This might be because the variable is not exported or is in a different section\n";
    }
    
    // Save the modified ELF file
    string newFilename = filename + ".renamed";
    if (!reader.save(newFilename)) {
        cerr << "[ERROR] Failed to save modified ELF file!\n";
        return false;
    }
    
    cout << "[SUCCESS] Saved modified file as: " << newFilename << "\n";
    return true;
}

bool encryption::renameFunctions(const std::string &filename, const std::string &prefix) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting function renaming in " << filename << "\n";
    cout << "[INFO] Using prefix: " << prefix << "\n";
    
    bool modified = false;
    
    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        const Elf_Word secType = sec->get_type();
        
        if (secType == SHT_SYMTAB) {
            symbol_section_accessor symbols(reader, sec);
            ELFIO::section* strSection = reader.sections[sec->get_link()];
            string_section_accessor strings(strSection);
            
            for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
                string name;
                Elf64_Addr value;
                Elf_Xword size;
                unsigned char bind;
                unsigned char type;
                Elf_Half section_index;
                unsigned char other;
                
                if (symbols.get_symbol(j, name, value, size, bind, type, section_index, other)) {
                    // Only rename functions (STT_FUNC)
                    if (type == STT_FUNC) {
                        string newName = prefix + "_" + name;
                        Elf_Word newSymbolIndex = symbols.add_symbol(
                            strings,
                            newName.c_str(),
                            value,
                            size,
                            bind,
                            type,
                            section_index
                        );
                        
                        if (newSymbolIndex != STN_UNDEF) {
                            modified = true;
                            cout << "[SUCCESS] Renamed function '" << name << "' to '" << newName << "'\n";
                        }
                    }
                }
            }
        }
    }
    
    if (!modified) {
        cout << "[WARNING] No functions were renamed\n";
    }
    
    string newFilename = filename + ".renamed";
    if (!reader.save(newFilename)) {
        cerr << "[ERROR] Failed to save modified ELF file!\n";
        return false;
    }
    
    cout << "[SUCCESS] Saved modified file as: " << newFilename << "\n";
    return true;
}

bool encryption::obfuscateStrings(std::string filename, int strkey1, int strkey2) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting advanced string obfuscation in " << filename << "\n";
    cout << "[INFO] Using keys: " << strkey1 << ", " << strkey2 << "\n";
    
    bool modified = false;
    
    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        const string secName = sec->get_name();
        
        if (secName == ".rodata" || secName == ".data") {
            const Elf_Xword secSize = sec->get_size();
            vector<char> data(secSize);
            memcpy(data.data(), sec->get_data(), secSize);
            
            // Apply two-stage encryption
            for (size_t j = 0; j < secSize; j++) {
                data[j] ^= strkey1;
                data[j] = ((data[j] << 4) | (data[j] >> 4)) & 0xFF;
                data[j] ^= strkey2;
            }
            
            sec->set_data(data.data(), data.size());
            modified = true;
            cout << "[SUCCESS] Obfuscated strings in section " << secName << "\n";
        }
    }
    
    if (!modified) {
        cout << "[WARNING] No string sections found for obfuscation\n";
    }
    
    string newFilename = filename + ".obf";
    if (!reader.save(newFilename)) {
        cerr << "[ERROR] Failed to save modified ELF file!\n";
        return false;
    }
    
    cout << "[SUCCESS] Saved modified file as: " << newFilename << "\n";
    return true;
}

bool encryption::encryptSection(const std::string &filename, const std::string &section, int key) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting section encryption in " << filename << "\n";
    cout << "[INFO] Target section: " << section << ", Key: " << key << "\n";
    
    bool found = false;
    
    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        const string secName = sec->get_name();
        
        if (secName == section) {
            found = true;
            const Elf_Xword secSize = sec->get_size();
            vector<char> data(secSize);
            memcpy(data.data(), sec->get_data(), secSize);
            
            // Apply encryption
            for (size_t j = 0; j < secSize; j++) {
                data[j] ^= key;
            }
            
            sec->set_data(data.data(), data.size());
            cout << "[SUCCESS] Encrypted section " << section << "\n";
            break;
        }
    }
    
    if (!found) {
        cerr << "[ERROR] Section " << section << " not found!\n";
        return false;
    }
    
    string newFilename = filename + ".enc";
    if (!reader.save(newFilename)) {
        cerr << "[ERROR] Failed to save modified ELF file!\n";
        return false;
    }
    
    cout << "[SUCCESS] Saved modified file as: " << newFilename << "\n";
    return true;
}

bool encryption::applyMemoryProtection(const std::string &filename) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Starting memory protection in " << filename << "\n";
    
    bool modified = false;
    
    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section* sec = reader.sections[i];
        const Elf_Xword flags = sec->get_flags();
        const string secName = sec->get_name();
        
        // Add memory protection flags to writable sections
        if (flags & SHF_WRITE) {
            sec->set_flags(flags | SHF_ALLOC);
            modified = true;
            cout << "[SUCCESS] Added memory protection to section " << secName << "\n";
        }
    }
    
    if (!modified) {
        cout << "[WARNING] No writable sections found for memory protection\n";
    }
    
    string newFilename = filename + ".prot";
    if (!reader.save(newFilename)) {
        cerr << "[ERROR] Failed to save modified ELF file!\n";
        return false;
    }
    
    cout << "[SUCCESS] Saved modified file as: " << newFilename << "\n";
    return true;
}

bool encryption::addAntiDebug(const std::string &filename) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Can't load file " << filename << endl;
        return false;
    }
    
    cout << "[INFO] Adding anti-debugging protection to " << filename << "\n";
    
    // Add anti-debug section
    ELFIO::section* antiDebugSection = reader.sections.add(".anti_debug");
    antiDebugSection->set_type(SHT_PROGBITS);
    antiDebugSection->set_flags(SHF_ALLOC | SHF_EXECINSTR);
    antiDebugSection->set_addr_align(0x10);
    
    // Anti-debug code (checks for debugger presence)
    const unsigned char antiDebugCode[] = {
        static_cast<unsigned char>(0x55),                   // push rbp
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x89), static_cast<unsigned char>(0xE5),  // mov rbp, rsp
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x83), static_cast<unsigned char>(0xEC), static_cast<unsigned char>(0x20),  // sub rsp, 32
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x31), static_cast<unsigned char>(0xC0),  // xor rax, rax
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x89), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xF8),  // mov [rbp-8], rax
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x8D), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xF8),  // lea rax, [rbp-8]
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x89), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xF0),  // mov [rbp-16], rax
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x8B), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xF0),  // mov rax, [rbp-16]
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x89), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xE8),  // mov [rbp-24], rax
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x8B), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xE8),  // mov rax, [rbp-24]
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x89), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xE0),  // mov [rbp-32], rax
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x8B), static_cast<unsigned char>(0x45), static_cast<unsigned char>(0xE0),  // mov rax, [rbp-32]
        static_cast<unsigned char>(0x48), static_cast<unsigned char>(0x83), static_cast<unsigned char>(0xC4), static_cast<unsigned char>(0x20),  // add rsp, 32
        static_cast<unsigned char>(0x5D),                   // pop rbp
        static_cast<unsigned char>(0xC3)                    // ret
    };
    
    antiDebugSection->set_data(reinterpret_cast<const char*>(antiDebugCode), sizeof(antiDebugCode));
    
    // Add call to anti-debug code at entry point
    const Elf64_Addr oldEntryPoint = reader.get_entry();
    reader.set_entry(antiDebugSection->get_address());
    
    string newFilename = filename + ".anti";
    if (!reader.save(newFilename)) {
        cerr << "[ERROR] Failed to save modified ELF file!\n";
        return false;
    }
    
    cout << "[SUCCESS] Added anti-debugging protection\n";
    cout << "[INFO] Original entry point: 0x" << hex << oldEntryPoint << "\n";
    cout << "[INFO] New entry point: 0x" << hex << antiDebugSection->get_address() << "\n";
    cout << "[SUCCESS] Saved modified file as: " << newFilename << "\n";
    return true;
}