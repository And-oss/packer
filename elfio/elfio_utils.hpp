#ifndef ELFIO_UTILS_HPP
#define ELFIO_UTILS_HPP

namespace ELFIO {

struct Elf_Half_Accessor {
    template <typename T>
    void set_half(T& value, Elf_Half new_value) {
        value = new_value;
    }

    template <typename T>
    Elf_Half get_half(const T& value) const {
        return value;
    }
};

struct generic_header_accessor {
    virtual ~generic_header_accessor() = default;
    virtual void save(std::ostream& f) const = 0;
    virtual bool load(std::istream& f) = 0;
};

template <typename T>
struct header_accessor : public generic_header_accessor {
    header_accessor(T& h) : header(h) {}

    void save(std::ostream& f) const override {
        f.write(reinterpret_cast<const char*>(&header), sizeof(header));
    }

    bool load(std::istream& f) override {
        return f.read(reinterpret_cast<char*>(&header), sizeof(header)).good();
    }

private:
    T& header;
};

} // namespace ELFIO

#endif
