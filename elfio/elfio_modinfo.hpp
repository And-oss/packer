#ifndef ELFIO_MODINFO_HPP
#define ELFIO_MODINFO_HPP

namespace ELFIO {

class modinfo_section_accessor {
public:
    modinfo_section_accessor(elfio& elf_file_, section* section_)
        : elf_file(elf_file_), modinfo_section(section_) {}

    bool get_attribute(unsigned int no, std::string& field, std::string& value) const {
        if (!modinfo_section || no >= get_attribute_num())
            return false;

        const char* pdata = modinfo_section->get_data();
        if (!pdata)
            return false;

        unsigned int current = 0;
        for (unsigned int i = 0; i < no; i++) {
            while (pdata[current] != '\0')
                current++;
            current++;
        }

        std::string attribute(pdata + current);
        size_t pos = attribute.find('=');
        if (pos != std::string::npos) {
            field = attribute.substr(0, pos);
            value = attribute.substr(pos + 1);
            return true;
        }

        return false;
    }

    unsigned int get_attribute_num() const {
        if (!modinfo_section)
            return 0;

        unsigned int count = 0;
        const char* pdata = modinfo_section->get_data();
        if (!pdata)
            return 0;

        unsigned int current = 0;
        while (current < modinfo_section->get_size()) {
            if (pdata[current] != '\0')
                current++;
            else {
                count++;
                current++;
            }
        }

        return count;
    }

    void add_attribute(const std::string& field, const std::string& value) {
        if (!modinfo_section)
            return;

        std::string attribute = field + "=" + value;
        attribute += '\0';

        const char* pdata = modinfo_section->get_data();
        std::string new_data;
        if (pdata)
            new_data.assign(pdata, modinfo_section->get_size());
        new_data += attribute;

        modinfo_section->set_data(new_data);
    }

private:
    elfio& elf_file;
    section* modinfo_section;
};

} // namespace ELFIO

#endif
