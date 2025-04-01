#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>

// Функции для защиты и обфускации исполняемых файлов ELF
namespace encryption {

    // Проверка, защищен ли файл с помощью PCK-формата
    bool isProtected(std::string filename);

    // Обфускация строковых констант
    bool obfuscateStrings(std::string filename, int strkey1 = 13, int strkey2 = 37);

    // Шифрование конкретной секции ELF-файла
    bool encryptSection(const std::string &filename, const std::string &section, int key);

    // Вставка мусорного кода для затруднения анализа
    bool insertJunkCode(std::string filename);

    // Модификация структуры ELF-файла (перестановка секций, изменение заголовков)
    void modifyELFStructure(const std::string &filename);

    // Добавление механизмов защиты от отладки
    bool addAntiDebug(const std::string &filename);

    // Добавление механизмов защиты памяти (проверка целостности, защита от модификации)
    bool applyMemoryProtection(const std::string &filename);

    // Переименование функций и символов для затруднения анализа
    bool renameFunctions(const std::string &filename, const std::string &prefix = "obf");

    // Упаковка ELF-файла (сжатие и добавление распаковщика)
    bool packELF(const std::string &filename);

    // Удаление или обфускация символов (имен функций, переменных)
    bool stripSymbols(const std::string &filename);

    // Добавление виртуальной машины для выполнения части кода
    bool addVirtualMachine(const std::string &filename);

    // Добавление PCK-заголовков в ELF-файл
    bool addPCKHeaders(std::string filename);

} // namespace encryption

#endif // ENCRYPTION_H