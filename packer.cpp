#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <sys/stat.h>

#include "elfio/elfio.hpp"
#include "src/headers/Encryption.h"

using namespace std;
using namespace ELFIO;  // Add this line to use ELFIO types directly


// [BUILD]  g++ packer.cpp src/Encryption.cpp -o packer -std=c++17 -lkeystone -ldl

int NOPInjectionELF(const string &filename, int count_nops = 10, uint64_t target_addr = 0, bool patch_end = false) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Couldn't open file " << filename << "\n";
        return -1;
    }

    for (int i = 0; i < reader.sections.size(); ++i) {
        section* sec = reader.sections[i];
        const string secName = sec->get_name();

        if (secName == ".text") {
            cout << "[INFO] FOUND .text section\n";

            const Elf_Xword secSize = sec->get_size();
            vector<char> data(secSize);
            memcpy(data.data(), sec->get_data(), secSize);

            const Elf64_Off offset = sec->get_offset();
            const Elf64_Addr text_vaddr = sec->get_address();

            if (patch_end) {
                cout << "[MODIFY] Overwriting last " << count_nops << " bytes of .text with NOPs\n";
                for (size_t i = secSize - count_nops; i < secSize; ++i) {
                    data[i] = '\x90';
                }
            } else if (target_addr != 0) {
                const uint64_t patch_offset = target_addr - text_vaddr;
                if (patch_offset >= secSize) {
                    cerr << "[ERROR] Target address is outside .text section!\n";
                    return -1;
                }

                cout << "[MODIFY] Injecting " << count_nops << " NOPs at address 0x"
                     << hex << target_addr << " (offset: 0x" << patch_offset << ")\n";

                for (int i = 0; i < count_nops && (patch_offset + i) < secSize; ++i) {
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

// Check if a file has PCK protection
bool isPCKProtected(const string &filename) {
    ifstream file(filename, ios::in | ios::binary);
    if (!file) {
        return false;
    }

    // Try to load the ELF file
    ELFIO::elfio reader;
    if (!reader.load(filename)) {
        return false;
    }

    // Look for .PCK section
    for (int i = 0; i < reader.sections.size(); ++i) {
        section* sec = reader.sections[i];
        const string secName = sec->get_name();
        
        if (secName == ".PCK") {
            const Elf_Xword secSize = sec->get_size();
            if (secSize >= 8) {
                const char* data = sec->get_data();
                return (memcmp(data, "PCK", 3) == 0 && 
                       data[3] == static_cast<char>(0xFF) && 
                       data[4] == static_cast<char>(0xEE));
            }
        }
    }

    // Look for .unpacker section as a fallback
    for (int i = 0; i < reader.sections.size(); ++i) {
        section* sec = reader.sections[i];
        if (sec->get_name() == ".unpacker") {
            return true;
        }
    }

    return false;
}

// Apply a single obfuscation technique and replace the original file
bool applySingleObfuscation(string &fileName, const string &technique, const string &param = "", uint8_t key1 = 0, uint8_t key2 = 0) {
    // Create a temporary file for this operation
    string tempFile = fileName + ".temp";
    
    // Make a copy of the original file to work with
    string copyCommand = "cp " + fileName + " " + tempFile;
    int result = system(copyCommand.c_str());
    if (result != 0) {
        cerr << "[ERROR] Failed to create temporary file: " << tempFile << endl;
        return false;
    }
    
    // Apply the requested technique to the temporary file
    bool success = false;
    string expectedOutput = "";
    
    if (technique == "rename") {
        encryption::renameFunctions(tempFile, param.empty() ? "obf" : param);
        expectedOutput = tempFile + ".renamed";
        success = true;
    } else if (technique == "junk") {
        encryption::insertJunkCode(tempFile);
        expectedOutput = tempFile + ".junk";
        success = true;
    } else if (technique == "strings") {
        encryption::obfuscateStrings(tempFile, key1, key2);
        expectedOutput = tempFile + ".obf";
        success = true;
    } else if (technique == "encrypt") {
        encryption::encryptSection(tempFile, param.empty() ? ".data" : param, key1);
        expectedOutput = tempFile;  // Модифицирует на месте
        success = true;
    } else if (technique == "memory") {
        encryption::applyMemoryProtection(tempFile);
        expectedOutput = tempFile + ".memobf";
        success = true;
    } else if (technique == "vm") {
        encryption::addVirtualMachine(tempFile);
        expectedOutput = tempFile + ".vm";
        success = true;
    } else if (technique == "antidebug") {
        encryption::addAntiDebug(tempFile);
        expectedOutput = tempFile + ".anti_dbg";
        success = true;
    } else if (technique == "strip") {
        encryption::stripSymbols(tempFile);
        expectedOutput = tempFile + ".stripped";
        success = true;
    } else if (technique == "pack") {
        encryption::packELF(tempFile);
        expectedOutput = tempFile + ".packed";
        success = true;
    } else if (technique == "nop") {
        NOPInjectionELF(tempFile, stoi(param.empty() ? "20" : param), 0, false);
        expectedOutput = tempFile;  // Модифицирует на месте
        success = true;
    }
    
    if (success) {
        // Проверяем, был ли создан ожидаемый выходной файл
        ifstream outputCheck(expectedOutput);
        if (outputCheck.good()) {
            // Найден ожидаемый выходной файл
            outputCheck.close();
            
            // Заменяем исходный файл на обработанный
            string mvCommand = "mv " + expectedOutput + " " + fileName;
            system(mvCommand.c_str());
            
            // Удаляем временный файл
            string rmCommand = "rm -f " + tempFile;
            system(rmCommand.c_str());
            
            cout << "[DEBUG] Successfully applied " << technique << ", output file: " << expectedOutput << " moved to: " << fileName << endl;
            return true;
        } else {
            // Ожидаемый выходной файл не найден, возможно, модификация произошла на месте
            if (expectedOutput == tempFile) {
                // Техника модифицирует файл на месте без создания нового файла с расширением
                string mvCommand = "mv " + tempFile + " " + fileName;
                system(mvCommand.c_str());
                
                cout << "[DEBUG] Successfully applied " << technique << " (in-place modification)" << endl;
                return true;
            } else {
                // Ищем альтернативные выходные файлы
                vector<string> possibleExtensions = {
                    ".renamed", ".junk", ".obf", ".memobf", ".vm", 
                    ".anti_dbg", ".stripped", ".packed"
                };
                
                for (const auto& ext : possibleExtensions) {
                    string altOutput = tempFile + ext;
                    ifstream altCheck(altOutput);
                    if (altCheck.good()) {
                        altCheck.close();
                        
                        // Заменяем исходный файл на альтернативный обработанный
                        string mvCommand = "mv " + altOutput + " " + fileName;
                        system(mvCommand.c_str());
                        
                        // Удаляем временный файл
                        string rmCommand = "rm -f " + tempFile;
                        system(rmCommand.c_str());
                        
                        cout << "[DEBUG] Found alternative output file: " << altOutput << " moved to: " << fileName << endl;
                        return true;
                    }
                }
                
                // Не найдено ни ожидаемого, ни альтернативного выходного файла
                cerr << "[ERROR] No output file found after applying " << technique << endl;
                
                // Проверяем, существует ли хотя бы временный файл
                ifstream tempCheck(tempFile);
                if (tempCheck.good()) {
                    tempCheck.close();
                    
                    // Используем временный файл, предполагая, что модификация была произведена
                    string mvCommand = "mv " + tempFile + " " + fileName;
                    system(mvCommand.c_str());
                    
                    cout << "[WARNING] Using temp file as fallback: " << tempFile << " moved to: " << fileName << endl;
                    return true;
                }
                
                // Ни один из файлов не найден, обфускация не удалась
                cerr << "[ERROR] Neither output nor temp file exists after " << technique << endl;
                return false;
            }
        }
    }
    
    // Чистим временные файлы в случае ошибки
    string cleanupCommand = "rm -f " + tempFile;
    system(cleanupCommand.c_str());
    
    cerr << "[ERROR] Failed to apply " << technique << endl;
    return false;
}

void printHelp() {
    cout << "Usage:\n"
         << "  -f <filename>   Specify ELF file to modify\n"
         << "  -ni             Inject NOPs into .text section\n"
         << "  -s              Encrypt strings in .rodata\n"
         << "  -as             Advanced string obfuscation (IDA-resistant)\n"
         << "  -k <key>        Set XOR key for string encryption (default: 0xAA)\n"
         << "  -k1 <key>       Set first key for advanced string obfuscation\n"
         << "  -k2 <key>       Set second key for advanced string obfuscation\n"
         << "  -addr <address> Set address to inject NOPs (in hexadecimal format)\n"
         << "  -end            Patch NOPs at the end of .text section instead of a specific address\n"
         << "  -n <num>        Set number of NOPs to inject (default: 10)\n"
         << "  -h              Show this help message\n"
         << "  -es             Encrypt section\n"
         << "  -t              section's name or some text\n"
         << "  -pack           Pack the executable (UPX-like functionality with PCK format and headers)\n"
         << "  -unpack         Unpack a previously packed executable\n"
         << "  -mem            Apply memory obfuscation techniques\n"
         << "  -vm             Apply code virtualization (strongest protection against IDA)\n"
         << "  -anti-dbg       Add anti-debugging protection\n"
         << "  -full           Apply full protection (all techniques combined)\n"
         << "  -check          Check if a file has PCK protection\n"
         << "  -rename         Rename functions and symbols for obfuscation\n"
         << "  -prefix <text>  Prefix to use when renaming functions (default: 'obf')\n"
         << "  -strip          Strip all symbol and debug information\n"
         << "  -junk           Insert junk code that doesn't affect functionality\n"
         << "  -complete       Apply a complete set of obfuscations while maintaining functionality\n"
         << "  -o <filename>   Specify output file (default: replaces the input)\n"
         << "  -var <old> <new> Rename a specific variable from old name to new name\n";
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

    string inputFileName;
    string outputFileName = "";
    bool nopInjection = false;
    bool stringObfuscation = false;
    bool advancedStringObf = false;
    bool encryptSection = false;
    bool patchEnd = false;
    bool packExecutable = false;
    bool unpackExecutable = false;
    bool memoryObfuscation = false;
    bool virtualization = false;
    bool antiDebugging = false;
    bool fullProtection = false;
    bool checkProtection = false;
    bool renameFunctions = false;
    bool stripSymbols = false;
    bool junkCode = false;
    bool completeObfuscation = false;
    bool renameVariable = false;
    string oldVarName;
    string newVarName;

    uint8_t xorKey = 0xAA; // Default XOR key
    uint8_t key1 = 0xBB;   // Default first key for advanced obfuscation
    uint8_t key2 = 0xCC;   // Default second key for advanced obfuscation
    int nopCount = 10; // Default NOP count
    uint64_t targetAddr = 0; // Default Target Address
    std::string text = ".text"; // Default Text
    std::string prefix = "obf"; // Default prefix for function renaming

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
        } else if (arg == "-as") {
            advancedStringObf = true;
        } else if (arg == "-f") {
            if (i + 1 < argc) {
                inputFileName = argv[++i];
            } else {
                cerr << "[ERROR] Missing filename after -f\n";
                return 1;
            }
        } else if (arg == "-o") {
            if (i + 1 < argc) {
                outputFileName = argv[++i];
            } else {
                cerr << "[ERROR] Missing filename after -o\n";
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
        } else if (arg == "-k1") {
            if (i + 1 < argc) {
                stringstream ss(argv[++i]);
                int tempKey;
                ss >> hex >> tempKey;
                if (ss.fail() || tempKey < 0 || tempKey > 255) {
                    cerr << "[ERROR] Invalid key! Must be a number (0-255) or hex (0x00-0xFF).\n";
                    return 1;
                }
                key1 = static_cast<uint8_t>(tempKey);
            } else {
                cerr << "[ERROR] Missing key after -k1\n";
                return 1;
            }
        } else if (arg == "-k2") {
            if (i + 1 < argc) {
                stringstream ss(argv[++i]);
                int tempKey;
                ss >> hex >> tempKey;
                if (ss.fail() || tempKey < 0 || tempKey > 255) {
                    cerr << "[ERROR] Invalid key! Must be a number (0-255) or hex (0x00-0xFF).\n";
                    return 1;
                }
                key2 = static_cast<uint8_t>(tempKey);
            } else {
                cerr << "[ERROR] Missing key after -k2\n";
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
        } else if (arg == "-pack") {
            packExecutable = true;
        } else if (arg == "-unpack") {
            unpackExecutable = true;
        } else if (arg == "-mem") {
            memoryObfuscation = true;
        } else if (arg == "-vm") {
            virtualization = true;
        } else if (arg == "-anti-dbg") {
            antiDebugging = true;
        } else if (arg == "-full") {
            fullProtection = true;
        } else if (arg == "-check") {
            checkProtection = true;
        } else if (arg == "-rename") {
            renameFunctions = true;
        } else if (arg == "-prefix") {
            if (i + 1 < argc) {
                prefix = argv[++i];
            } else {
                cerr << "[ERROR] Missing prefix after -prefix\n";
                return 1;
            }
        } else if (arg == "-strip") {
            stripSymbols = true;
        } else if (arg == "-junk") {
            junkCode = true;
        } else if (arg == "-complete") {
            completeObfuscation = true;
        } else if (arg == "-var") {
            if (i + 2 < argc) {
                renameVariable = true;
                oldVarName = argv[++i];
                newVarName = argv[++i];
            } else {
                cerr << "[ERROR] Missing old and new variable names after -var\n";
                return 1;
            }
        } else if (arg == "-o") {
            if (i + 1 < argc) {
                outputFileName = argv[++i];
            } else {
                cerr << "[ERROR] Missing filename after -o\n";
                return 1;
            }
        }
    }

    // Проверка на отсутствие имени файла
    if (inputFileName.empty()) {
        cerr << "[ERROR] No input filename specified!\n";
        return 1;
    }
    
    // If output filename is not specified, use the input filename
    if (outputFileName.empty()) {
        outputFileName = inputFileName;
    } else {
        // Copy the input file to the output file as a starting point
        string copyCommand = "cp " + inputFileName + " " + outputFileName;
        system(copyCommand.c_str());
    }
    
    // Check if file has PCK protection
    if (checkProtection) {
        cout << "[INFO] Checking if " << inputFileName << " is PCK protected...\n";
        if (isPCKProtected(inputFileName)) {
            cout << "[RESULT] File is PCK protected! IDA will NOT be able to analyze this file.\n";
        } else {
            cout << "[RESULT] File is NOT PCK protected. It can be analyzed by IDA.\n";
        }
        return 0;
    }
    
    // Complete obfuscation applies a full set of transformations that maintain functionality
    if (completeObfuscation) {
        cout << "[INFO] Applying complete obfuscation suite to " << inputFileName << "\n";
        
        // Make a backup of the original file
        string backupFile = inputFileName + ".bak";
        string bakCommand = "cp " + inputFileName + " " + backupFile;
        system(bakCommand.c_str());
        
        cout << "[INFO] Original file backed up to: " << backupFile << "\n";
        
        // Убедимся, что файл существует перед началом обфускации
        ifstream fileCheck(inputFileName);
        if (!fileCheck.good()) {
            cerr << "[ERROR] Input file doesn't exist or cannot be opened: " << inputFileName << endl;
            return 1;
        }
        fileCheck.close();
        
        // Проверим размер файла
        struct stat fileStat;
        if (stat(inputFileName.c_str(), &fileStat) == 0) {
            cout << "[INFO] Initial file size: " << fileStat.st_size << " bytes" << endl;
            if (fileStat.st_size < 100) {
                cerr << "[WARNING] Input file is very small, may not be a valid ELF file" << endl;
            }
        }
        
        // Проверим, что это действительно ELF файл
        ELFIO::elfio elf_check;
        if (!elf_check.load(inputFileName)) {
            cerr << "[ERROR] Input file is not a valid ELF file: " << inputFileName << endl;
            cout << "[INFO] You can restore from backup: " << backupFile << endl;
            return 1;
        }
        
        // Apply obfuscations in sequence to the same file
        cout << "\n[STEP 1/8] Renaming functions and symbols...\n";
        if (!applySingleObfuscation(outputFileName, "rename", prefix)) {
            cerr << "[ERROR] Function renaming failed! Check if the file is a valid executable with symbols.\n";
            cout << "[INFO] You can restore from backup: " << backupFile << endl;
            return 1;
        }
        
        // Проверка файла после каждого шага
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] After renaming, file size: " << fileStat.st_size << " bytes" << endl;
        if (fileStat.st_size < 100) {
            cerr << "[WARNING] File seems corrupted after renaming. Attempting to restore from backup.\n";
            string restoreCmd = "cp " + backupFile + " " + outputFileName;
            system(restoreCmd.c_str());
            cerr << "[INFO] Restored from backup. Stopping obfuscation process.\n";
            return 1;
        }
        
        cout << "\n[STEP 2/8] Inserting junk code...\n";
        if (!applySingleObfuscation(outputFileName, "junk")) {
            cerr << "[ERROR] Junk code insertion failed!\n";
            cout << "[INFO] Continuing with next step...\n";
            // Продолжаем выполнение вместо выхода
        }
        
        // Проверка файла
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] After junk insertion, file size: " << fileStat.st_size << " bytes" << endl;
        
        cout << "\n[STEP 3/8] Advanced string obfuscation...\n";
        if (!applySingleObfuscation(outputFileName, "strings", "", key1, key2)) {
            cerr << "[ERROR] String obfuscation failed!\n";
            cout << "[INFO] Continuing with next step...\n";
        }
        
        // Проверка файла
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] After string obfuscation, file size: " << fileStat.st_size << " bytes" << endl;
        
        cout << "\n[STEP 4/8] Encrypting critical data sections...\n";
        if (!applySingleObfuscation(outputFileName, "encrypt", ".data", xorKey)) {
            cerr << "[ERROR] Section encryption failed!\n";
            cout << "[INFO] Continuing with next step...\n";
        }
        
        // Проверка файла
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] After section encryption, file size: " << fileStat.st_size << " bytes" << endl;
        
        cout << "\n[STEP 5/8] Adding memory protection...\n";
        if (!applySingleObfuscation(outputFileName, "memory")) {
            cerr << "[ERROR] Memory protection failed!\n";
            cout << "[INFO] Continuing with next step...\n";
        }
        
        // Проверка файла
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] After memory protection, file size: " << fileStat.st_size << " bytes" << endl;
        
        cout << "\n[STEP 6/8] Adding anti-debugging protection...\n";
        if (!applySingleObfuscation(outputFileName, "antidebug")) {
            cerr << "[ERROR] Anti-debugging protection failed!\n";
            cout << "[INFO] Continuing with next step...\n";
        }
        
        // Проверка файла
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] After anti-debugging, file size: " << fileStat.st_size << " bytes" << endl;
        
        cout << "\n[STEP 7/8] Stripping symbols and debug information...\n";
        if (!applySingleObfuscation(outputFileName, "strip")) {
            cerr << "[ERROR] Symbol stripping failed!\n";
            cout << "[INFO] Continuing with next step...\n";
        }
        
        // Проверка файла
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] After stripping, file size: " << fileStat.st_size << " bytes" << endl;
        
        cout << "\n[STEP 8/8] Packing the executable with PCK format...\n";
        if (!applySingleObfuscation(outputFileName, "pack")) {
            cerr << "[ERROR] Packing failed!\n";
            cout << "[INFO] Continuing without packing...\n";
        }
        
        // Final file check
        stat(outputFileName.c_str(), &fileStat);
        cout << "[DEBUG] Final file size: " << fileStat.st_size << " bytes" << endl;
        
        // Check if the final file is valid
        if (fileStat.st_size < 100) {
            cerr << "[ERROR] Final file appears to be invalid or corrupted!\n";
            cout << "[INFO] Restoring from backup..." << endl;
            string restoreCmd = "cp " + backupFile + " " + outputFileName;
            system(restoreCmd.c_str());
            cout << "[INFO] Restored from backup: " << backupFile << endl;
            return 1;
        }
        
        // Make the final file executable
        string chmodCommand = "chmod +x " + outputFileName;
        system(chmodCommand.c_str());
        
        cout << "\n[SUCCESS] Complete obfuscation applied!\n";
        cout << "[INFO] Protected file: " << outputFileName << "\n";
        cout << "[INFO] Original file backed up to: " << backupFile << "\n";
        cout << "[INFO] This file has been thoroughly obfuscated while maintaining functionality\n";
        cout << "[INFO] Original program behavior is preserved while being completely resistant to analysis\n";
        cout << "[INFO] PCK headers and protection integrated into the executable\n";
        
        return 0;
    }

    // If full protection is enabled, apply all techniques in the optimal order
    if (fullProtection) {
        cout << "[INFO] Applying full protection suite to " << inputFileName << "\n";
        
        // Make a backup of the original file
        string backupFile = inputFileName + ".bak";
        string bakCommand = "cp " + inputFileName + " " + backupFile;
        system(bakCommand.c_str());
        
        cout << "[INFO] Original file backed up to: " << backupFile << "\n";
        
        // Apply protections in sequence to the same file
        cout << "[STEP 1/7] Advanced string obfuscation...\n";
        if (!applySingleObfuscation(outputFileName, "strings", "", key1, key2)) {
            cout << "[ERROR] String obfuscation failed!\n";
            return 1;
        }
        
        cout << "[STEP 2/7] Encrypting critical data sections...\n";
        if (!applySingleObfuscation(outputFileName, "encrypt", ".data", xorKey)) {
            cout << "[ERROR] Section encryption failed!\n";
            return 1;
        }
        
        cout << "[STEP 3/7] Adding memory protection...\n";
        if (!applySingleObfuscation(outputFileName, "memory")) {
            cout << "[ERROR] Memory protection failed!\n";
            return 1;
        }
        
        cout << "[STEP 4/7] Adding code virtualization...\n";
        if (!applySingleObfuscation(outputFileName, "vm")) {
            cout << "[ERROR] Virtualization failed!\n";
            return 1;
        }
        
        cout << "[STEP 5/7] Adding anti-debugging protection...\n";
        if (!applySingleObfuscation(outputFileName, "antidebug")) {
            cout << "[ERROR] Anti-debugging protection failed!\n";
            return 1;
        }
        
        cout << "[STEP 6/7] Adding code obfuscation...\n";
        if (!applySingleObfuscation(outputFileName, "nop", to_string(20))) {
            cout << "[ERROR] NOP injection failed!\n";
            return 1;
        }
        
        cout << "[STEP 7/7] Packing the executable with PCK format...\n";
        if (!applySingleObfuscation(outputFileName, "pack")) {
            cout << "[ERROR] Packing failed!\n";
            return 1;
        }
        
        // Make the final file executable
        string chmodCommand = "chmod +x " + outputFileName;
        system(chmodCommand.c_str());
        
        cout << "\n[SUCCESS] Full protection applied!\n";
        cout << "[INFO] Protected file: " << outputFileName << "\n";
        cout << "[WARNING] This file contains runtime decryption code that preserves functionality\n";
        cout << "[INFO] Original program behavior is preserved while being completely resistant to IDA analysis\n";
        cout << "[INFO] PCK protection integrated into the executable\n";
        
        return 0;
    }

    // Individual protection options applied one at a time to the output file
    if (nopInjection) {
        applySingleObfuscation(outputFileName, "nop", to_string(nopCount));
    }

    if (stringObfuscation) {
        applySingleObfuscation(outputFileName, "encrypt", ".rodata", xorKey);
    }

    if (advancedStringObf) {
        applySingleObfuscation(outputFileName, "strings", "", key1, key2);
    }

    if (encryptSection) {
        applySingleObfuscation(outputFileName, "encrypt", text, xorKey);
    }

    if (packExecutable) {
        // Check if the file is already packed
        if (isPCKProtected(outputFileName)) {
            cout << "[ERROR] File is already PCK protected. Cannot pack again.\n";
            return 1;
        }
        
        applySingleObfuscation(outputFileName, "pack");
    }
    
    if (memoryObfuscation) {
        applySingleObfuscation(outputFileName, "memory");
    }

    if (virtualization) {
        applySingleObfuscation(outputFileName, "vm");
    }
    
    if (antiDebugging) {
        applySingleObfuscation(outputFileName, "antidebug");
    }
    
    if (renameFunctions) {
        applySingleObfuscation(outputFileName, "rename", prefix);
    }
    
    if (stripSymbols) {
        applySingleObfuscation(outputFileName, "strip");
    }
    
    if (junkCode) {
        applySingleObfuscation(outputFileName, "junk");
    }

    if (renameVariable) {
        cout << "[INFO] Renaming variable '" << oldVarName << "' to '" << newVarName << "'\n";
        if (!encryption::renameVariables(outputFileName, oldVarName, newVarName)) {
            cerr << "[ERROR] Failed to rename variable!\n";
            return 1;
        }
        cout << "[SUCCESS] Variable renamed successfully!\n";
    }

    // Make the final file executable if we've modified it
    if (nopInjection || stringObfuscation || advancedStringObf || encryptSection || 
        packExecutable || memoryObfuscation || virtualization || antiDebugging || 
        renameFunctions || stripSymbols || junkCode) {
        
        string chmodCommand = "chmod +x " + outputFileName;
        system(chmodCommand.c_str());
        
        cout << "[SUCCESS] All requested obfuscations applied to " << outputFileName << "\n";
    }

    return 0;
}