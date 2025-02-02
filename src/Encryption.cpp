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

        cerr << "[ERROR] Секция .rodata не найдена!\n";
}

void encryption::encryptSection(const std::string &filename, const std::string &sectionName, uint8_t key) {
    ELFIO::elfio reader;

    if (!reader.load(filename)) {
        cerr << "[ERROR] Ошибка загрузки ELF!\n";
        return;
    }

    for (int i = 0; i < reader.sections.size(); ++i) {
        ELFIO::section *sec = reader.sections[i];

        if (sec->get_name() == sectionName) {
            cout << "[INFO] FOUND " << sectionName << "\n";

            vector<char> data(sec->get_size());
            memcpy(data.data(), sec->get_data(), sec->get_size());

            for (char &c : data) c ^= key;

            streampos offset = sec->get_offset();
            cout << "[LEAK] " << sectionName << " offset: " << offset << "\n";

            fstream file(filename, ios::in | ios::out | ios::binary);
            if (!file) {
                cerr << "[ERROR] Ошибка открытия ELF-файла для записи!\n";
                return;
            }

            file.seekp(offset);
            file.write(data.data(), data.size());
            file.close();

            cout << "[SUCCESS] Секция " << sectionName << " зашифрована с ключом " << hex << "0x" << (int)key << "!\n";
            return;
        }
    }

    cerr << "[ERROR] Секция " << sectionName << " не найдена!\n";
}