#ifndef ELFIO_DUMP_HPP
#define ELFIO_DUMP_HPP

namespace ELFIO {

class dump {
public:
    static std::string section_flags( Elf_Xword flags ) {
        std::string ret = "";
        if ( flags & SHF_WRITE ) {
            ret += "W";
        }
        if ( flags & SHF_ALLOC ) {
            ret += "A";
        }
        if ( flags & SHF_EXECINSTR ) {
            ret += "X";
        }
        if ( flags & SHF_MERGE ) {
            ret += "M";
        }
        if ( flags & SHF_STRINGS ) {
            ret += "S";
        }
        if ( flags & SHF_INFO_LINK ) {
            ret += "I";
        }
        if ( flags & SHF_LINK_ORDER ) {
            ret += "L";
        }
        if ( flags & SHF_OS_NONCONFORMING ) {
            ret += "O";
        }
        if ( flags & SHF_GROUP ) {
            ret += "G";
        }
        if ( flags & SHF_TLS ) {
            ret += "T";
        }
        if ( flags & SHF_COMPRESSED ) {
            ret += "C";
        }
        if ( flags & SHF_EXCLUDE ) {
            ret += "E";
        }
        if ( flags & SHF_GNU_MBIND ) {
            ret += "D";
        }

        return ret;
    }

#undef DUMP_DEC_FORMAT
#undef DUMP_HEX0x_FORMAT
#undef DUMP_STR_FORMAT
}; 
} 

#endif
