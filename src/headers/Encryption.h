#ifndef PACKER_ENCRYPTION_H
#define PACKER_ENCRYPTION_H

#include <string>

namespace encryption {

    // Шифрование строк в ELF-файле
    void encryptStrings(const std::string &filename, uint8_t key);

    // Переименование функций в ELF-файле
    void renameFunctions(const std::string &filename, std::string &text);

    // Шифрование конкретной секции ELF-файла
    void encryptSection(const std::string &filename, const std::string &sectionName, uint8_t key);

    // Вставка мусорного кода для затруднения анализа
    void insertJunkCode(const std::string &filename);

    // Модификация структуры ELF-файла (перестановка секций, изменение заголовков)
    void modifyELFStructure(const std::string &filename);

    // Добавление проверки целостности файла (например, хэш-суммы)
    void addIntegrityCheck(const std::string &filename);

    // Добавление анти-отладочных механизмов
    void addAntiDebugging(const std::string &filename);

    // Упаковка ELF-файла (сжатие и добавление распаковщика)
    void packELF(const std::string &filename);

    // Динамическая обфускация (расшифровка кода во время выполнения)
    void addDynamicObfuscation(const std::string &filename);

    // Удаление или обфускация символов (имен функций, переменных)
    void stripSymbols(const std::string &filename);

    // Добавление виртуальной машины для выполнения части кода
    void addVirtualMachine(const std::string &filename);

    // Проверка окружения (например, обнаружение виртуальных машин или отладчиков)
    void addEnvironmentChecks(const std::string &filename);

    // Добавление ложных вызовов функций для запутывания анализатора
    void addFakeCalls(const std::string &filename);

    // Шифрование метаданных ELF-файла (заголовки, таблицы символов и т.д.)
    void encryptMetadata(const std::string &filename, uint8_t key);

    // Рандомизация адресов функций и данных
    void randomizeAddresses(const std::string &filename);

    // Добавление полиморфного кода (код, который изменяется при каждом запуске)
    void addPolymorphicCode(const std::string &filename);

    // Логирование и мониторинг попыток анализа или взлома
    void addMonitoring(const std::string &filename);

    // Удаление отладочной информации (например, секции .debug)
    void removeDebugInfo(const std::string &filename);

    // Изменение точек входа (entry point) для затруднения анализа
    void modifyEntryPoint(const std::string &filename, uint32_t newEntryPoint);

    // Добавление водяных знаков или скрытых меток для идентификации файла
    void addWatermark(const std::string &filename, const std::string &watermark);

    // Шифрование relocations (таблиц перемещений)
    void encryptRelocations(const std::string &filename, uint8_t key);

    // Добавление ложных секций для запутывания анализатора
    void addFakeSections(const std::string &filename);

    // Изменение флагов секций для затруднения анализа
    void modifySectionFlags(const std::string &filename);

} // namespace encryption


#endif // PACKER_ENCRYPTION_H