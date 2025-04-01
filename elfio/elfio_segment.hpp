#ifndef ELFIO_SEGMENT_HPP
#define ELFIO_SEGMENT_HPP

namespace ELFIO {

class segment {
public:
    virtual ~segment() = default;

    virtual Elf_Half get_index() const = 0;
    virtual Elf_Word get_type() const = 0;
    virtual Elf_Word get_flags() const = 0;
    virtual Elf_Xword get_align() const = 0;
    virtual Elf_Xword get_size_in_file() const = 0;
    virtual Elf_Xword get_memory_size() const = 0;
    virtual Elf64_Addr get_virtual_address() const = 0;
    virtual Elf64_Addr get_physical_address() const = 0;
    virtual const char* get_data() const = 0;

    virtual void set_type( Elf_Word value ) = 0;
    virtual void set_flags( Elf_Word value ) = 0;
    virtual void set_align( Elf_Xword value ) = 0;
    virtual void set_size_in_file( Elf_Xword value ) = 0;
    virtual void set_memory_size( Elf_Xword value ) = 0;
    virtual void set_virtual_address( Elf64_Addr value ) = 0;
    virtual void set_physical_address( Elf64_Addr value ) = 0;
    virtual void set_data( const char* data, Elf_Word size ) = 0;
    virtual void append_data( const char* data, Elf_Word size ) = 0;
};

} // namespace ELFIO

#endif
