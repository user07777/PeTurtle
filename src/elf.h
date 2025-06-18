#ifndef ELF_H
#define ELF_H

#define EI_NIDENT 16

// C Standard Library
#include <cstdio>
#include <cstring>
#include <cmath>

// C++ Standard Library
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <variant>
#include <filesystem>
#include <map>
#include <cxxabi.h>
#include <memory>
#include <algorithm>
// System-specific (Linux/ELF)
#include <elf.h>

//Mine
#include "utils.h"


class ElfStudio {
public:
    explicit ElfStudio(std::filesystem::path filepath) : path(std::move(filepath)) {
        parse();
    }
    explicit ElfStudio() {
    }


    // return the elf arch
    [[nodiscard]] std::string getArch() const {
        return std::visit([](auto&& hdr) -> std::string {
            switch (hdr.e_machine) {
                case EM_X86_64: return "x86-64";
                case EM_386:    return "i386";
                case EM_ARM:    return "ARM";
                case EM_AARCH64:return "AArch64";
                default:        return "Unknown";
            }
        }, header);
    }

    // return the elf type
    [[nodiscard]] std::string getType() const {
        return std::visit([](auto&& hdr) -> std::string {
            switch (hdr.e_type) {
                case ET_NONE:  return "unknown";
                case ET_REL:   return "relocatable";
                case ET_EXEC:  return "executable";
                case ET_DYN:   return "shared object";
                case ET_CORE:  return "core";
                default:       return "unknown";
            }
        }, header);
    }

    //return general info about the elf
    [[nodiscard]] ElfInfo getInfo() const {
        return std::visit([](auto&& hdr) -> ElfInfo {
            return {
                hdr.e_entry,
                hdr.e_phoff,
                hdr.e_shoff,
                hdr.e_flags,
                hdr.e_ehsize,
                hdr.e_phentsize,
                hdr.e_phnum,
                hdr.e_shentsize,
                hdr.e_shnum,
                hdr.e_shstrndx
            };
        }, header);
    }
    //get compiler name
    [[nodiscard]] std::string getCompiler() const {
        auto sections = getSections();
        const auto it = std::find_if(sections.begin(), sections.end(),
            [](const auto& sec) { return sec.name == ".comment"; });

        if (it == sections.end()) {
            return "Unknown";
        }

        return std::visit([&](auto&& hdr) -> std::string {
            if (fseek(file, it->offset, SEEK_SET) != 0) {
                return "Error seeking";
            }

            std::vector<char> buffer(it->size);
            size_t read = fread(buffer.data(), 1, it->size, file);

            if (read != it->size) {
                return "Error reading";
            }

            return std::string(buffer.data(), strnlen(buffer.data(), it->size));
        }, header);
    }

    //return general info about the section
    [[nodiscard]] std::vector<Section> getSections() const {
        std::vector<Section> sections;



        fseek(file, 0, SEEK_END);
        long file_size = ftell(file);
        rewind(file);

        auto [shstr_offset, shstr_size] = std::visit([&](auto&& hdr) -> std::pair<uint64_t, uint64_t> {
            using HdrT = std::decay_t<decltype(hdr)>;
            using ShdrT = std::conditional_t<std::is_same_v<HdrT, Elf64_Ehdr>, Elf64_Shdr, Elf32_Shdr>;

            ShdrT shstr{};
            long shstr_offset_in_file = hdr.e_shoff + hdr.e_shstrndx * hdr.e_shentsize;
            fseek(file, shstr_offset_in_file, SEEK_SET);
            fread(&shstr, 1, sizeof(shstr), file);
            return {shstr.sh_offset, shstr.sh_size};
        }, header);

        if (shstr_offset + shstr_size > file_size) {
            throw std::runtime_error("String table > file size.");
        }

        std::vector<char> shstrtab(shstr_size);
        fseek(file, shstr_offset, SEEK_SET);
        fread(shstrtab.data(), 1, shstrtab.size(), file);

        std::visit([&](auto&& hdr) {
            using HdrT = std::decay_t<decltype(hdr)>;
            using ShdrT = std::conditional_t<std::is_same_v<HdrT, Elf64_Ehdr>, Elf64_Shdr, Elf32_Shdr>;

            for (int i = 0; i < hdr.e_shnum; ++i) {
                ShdrT sh{};
                fseek(file, hdr.e_shoff + i * hdr.e_shentsize, SEEK_SET);
                fread(&sh, 1, sizeof(sh), file);

                std::string name = (sh.sh_name < shstrtab.size()) ? std::string(&shstrtab[sh.sh_name]) : "<invalid>";

                double ent = 0.0;
                if (sh.sh_size != 0 && sh.sh_offset != 0 && sh.sh_offset + sh.sh_size <= file_size) {
                    std::vector<uint8_t> data(sh.sh_size);
                    fseek(file, sh.sh_offset, SEEK_SET);
                    fread(data.data(), 1, data.size(), file);
                    ent = getEntropy(data);
                }

                sections.push_back({
                    name,
                    sh.sh_addr,
                    sh.sh_offset,
                    sh.sh_size,
                    getSectType(sh.sh_type),
                    ent
                });
            }
        }, header);

        return sections;
    }
    //get file entropy
    [[nodiscard]] double getFileEntropy() const {
        if (fseek(file, 0, SEEK_END) != 0) {
            return 0.0;
        }
        long fileSize = ftell(file);
        rewind(file);

        if (fileSize <= 0) {
            return 0.0;
        }

        std::vector<uint8_t> buffer(fileSize);
        size_t read = fread(buffer.data(), 1, fileSize, file);

        if (read != fileSize) {
            return 0.0;
        }

        return getEntropy(buffer);
    }


    //return general info about the program
    [[nodiscard]] std::vector<Program> getProgram() const {
        return std::visit([&](auto&& hdr) -> std::vector<Program> {
            const bool is64 = std::holds_alternative<Elf64_Ehdr>(header);
            std::vector<Program> prog;

            auto type2Str = [](const uint32_t type) -> std::string {
                switch (type) {
                    case PT_NULL:         return "NULL";
                    case PT_LOAD:         return "LOAD";
                    case PT_DYNAMIC:      return "DYNAMIC";
                    case PT_INTERP:       return "INTERP";
                    case PT_NOTE:         return "NOTE";
                    case PT_SHLIB:        return "SHLIB";
                    case PT_PHDR:         return "PHDR";
                    case PT_TLS:          return "TLS";
                    case 0x6474e550:      return "GNU_EH_FRAME";
                    case 0x6474e551:      return "GNU_STACK";
                    case 0x6474e552:      return "GNU_RELRO";
                    case 0x6ffffffa:      return "SUNWBSS";
                    case 0x6ffffffb:      return "SUNWSTACK";
                    case 0x6ffffffe:      return "LOOS";
                    case 0x6fffffff:      return "HIOS";
                    case 0x70000000:      return "LOPROC";
                    case 0x7fffffff:      return "HIPROC";
                    default:
                        if (type >= 0x60000000 && type <= 0x6fffffff) return "OS_SPECIFIC";
                        if (type >= 0x70000000 && type <= 0x7fffffff) return "PROC_SPECIFIC";
                        return "UNKNOWN";
                }
            };

            auto flags2Str = [](const uint32_t flags) -> std::string {
                std::string s;
                s += (flags & PF_R) ? 'R' : '-';
                s += (flags & PF_W) ? 'W' : '-';
                s += (flags & PF_X) ? 'E' : '-';
                return s;
            };

            long phoff = hdr.e_phoff;
            long phentsize = hdr.e_phentsize;
            long phnum = hdr.e_phnum;

            if (phoff == 0 || phentsize == 0 || phnum == 0) {
                throw std::runtime_error("No program headers.");
            }

            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            rewind(file);

            if (phoff + (phentsize * phnum) > file_size) {
                throw std::runtime_error("Program header table > file size.");
            }

            fseek(file, phoff, SEEK_SET);

            for (int i = 0; i < phnum; ++i) {
                if (is64) {
                    Elf64_Phdr ph{};
                    fread(&ph, 1, sizeof(ph), file);

                    prog.push_back({
                        type2Str(ph.p_type),
                        ph.p_offset,
                        ph.p_vaddr,
                        ph.p_paddr,
                        ph.p_filesz,
                        ph.p_memsz,
                        flags2Str(ph.p_flags),
                        ph.p_align
                    });
                } else {
                    Elf32_Phdr ph{};
                    fread(&ph, 1, sizeof(ph), file);

                    prog.push_back({
                        type2Str(ph.p_type),
                        ph.p_offset,
                        ph.p_vaddr,
                        ph.p_paddr,
                        ph.p_filesz,
                        ph.p_memsz,
                        flags2Str(ph.p_flags),
                        ph.p_align
                    });
                }
            }

            return prog;
        }, header);
    }

    //dump strings
    [[nodiscard]] std::vector<std::string> dumpStrings() const {
        std::vector<std::string> result;

        fseek(file, 0, SEEK_END);
        int fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);

        std::vector<char> data(fileSize);
        fread(data.data(), 1, fileSize, file);

        int i = 0;
        while (i < fileSize) {
            if (isprint(data[i])) {
                int start = i;
                while (i < fileSize && isprint(data[i])) {
                    i++;
                }
                int len = i - start;
                if (len >= 4) {
                    result.emplace_back(&data[start], len);
                }
            } else {
                i++;
            }
        }

        return result;
    }
    //get exported functions
    [[nodiscard]] std::vector<EAT> getEAT() const {
        std::vector<EAT> exports;
        auto [dynsym_offset, dynsym_size, dynsym_entsize] = getSect(".dynsym");
        auto [dynstr_offset, dynstr_size,a] = getSect(".dynstr");

        int count = dynsym_size / dynsym_entsize;

        std::vector<char> strtab(dynstr_size);
        fseek(file, dynstr_offset, SEEK_SET);
        fread(strtab.data(), 1, strtab.size(), file);

        for (int i = 0; i < count; ++i) {
            Elf64_Sym sym{};
            fseek(file, dynsym_offset + i * dynsym_entsize, SEEK_SET);
            fread(&sym, 1, sizeof(sym), file);

            if (sym.st_shndx != SHN_UNDEF) {
                std::string name = (sym.st_name < strtab.size()) ? &strtab[sym.st_name] : "<noname>";
                exports.push_back({demangle(name.c_str()), sym.st_value});
            }
        }
        return exports;
    }
    //get imported functions
    [[nodiscard]] std::vector<IAT> getIAT() const {
        std::vector<IAT> imports;

        auto [dynsym_offset, dynsym_size, dynsym_entsize] = getSect(".dynsym");
        auto [dynstr_offset, dynstr_size,dynstr_entsize] = getSect(".dynstr");
        auto [relaplt_offset, relaplt_size, relaplt_entsize] = getSect(".rela.plt");

        std::vector<char> strtab(dynstr_size);
        fseek(file, dynstr_offset, SEEK_SET);
        fread(strtab.data(), 1, strtab.size(), file);

        int reloc_count = relaplt_size / relaplt_entsize;

        for (int i = 0; i < reloc_count; ++i) {
            Elf64_Rela rela{};
            fseek(file, relaplt_offset + i * relaplt_entsize, SEEK_SET);
            fread(&rela, 1, sizeof(rela), file);

            int sym_index = ELF64_R_SYM(rela.r_info);
            Elf64_Sym sym{};
            fseek(file, dynsym_offset + sym_index * dynsym_entsize, SEEK_SET);
            fread(&sym, 1, sizeof(sym), file);

            std::string name = (sym.st_name < strtab.size()) ? &strtab[sym.st_name] : "<noname>";

            imports.push_back({demangle(name.c_str()), rela.r_offset});
        }

        return imports;
    }

    [[nodiscard]]  std::vector<std::string> VirusTotal() const{};

    [[nodiscard]]  std::vector<std::string> Yara() const{};

    ~ElfStudio() {}
private:
    std::filesystem::path path;
    std::variant<Elf32_Ehdr, Elf64_Ehdr> header;
    FILE* file;

    void parse() {
        file = fopen(path.c_str(), "rb");
        if (!file) {
            throw std::runtime_error("Can't open file.");
        }

        unsigned char ident[EI_NIDENT];
        if (fread(ident, 1, EI_NIDENT, file) != EI_NIDENT) {
            fclose(file);
            throw std::runtime_error("Can't read ELF ident.");
        }

        if (ident[EI_MAG0] != ELFMAG0 ||
            ident[EI_MAG1] != ELFMAG1 ||
            ident[EI_MAG2] != ELFMAG2 ||
            ident[EI_MAG3] != ELFMAG3) {
            fclose(file);
            throw std::runtime_error("Not valid ELF");
        }

        if (ident[EI_CLASS] == ELFCLASS32) {
            Elf32_Ehdr hdr32{};
            memcpy(hdr32.e_ident, ident, EI_NIDENT);
            if (fread(&hdr32.e_type, 1, sizeof(hdr32) - EI_NIDENT, file) != sizeof(hdr32) - EI_NIDENT) {
                fclose(file);
                throw std::runtime_error("Can't read ELF32 header.");
            }
            header = hdr32;
        } else if (ident[EI_CLASS] == ELFCLASS64) {
            Elf64_Ehdr hdr64{};
            memcpy(hdr64.e_ident, ident, EI_NIDENT);
            if (fread(&hdr64.e_type, 1, sizeof(hdr64) - EI_NIDENT, file) != sizeof(hdr64) - EI_NIDENT) {
                fclose(file);
                throw std::runtime_error("Can't read ELF64 header.");
            }
            header = hdr64;
        } else {
            fclose(file);
            throw std::runtime_error("Unknown ELF class.");
        }
    }
    //calculates section entropy
    static double getEntropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0;
        double entropy = 0.0;
        uint64_t freq[256] = {0};

        for (uint8_t byte : data) freq[byte]++;
        for (uint64_t f : freq) {
            if (f == 0) continue;
            double p = static_cast<double>(f) / data.size();
            entropy -= p * std::log2(p);
        }

        return entropy;
    }
    //convert uint32_t type to std::string
    static std::string getSectType(uint32_t sh_type) {
        switch (sh_type) {
            case 0: return "NULL";
            case 1: return "PROGBITS";
            case 2: return "SYMTAB";
            case 3: return "STRTAB";
            case 4: return "RELA";
            case 5: return "HASH";
            case 6: return "DYNAMIC";
            case 7: return "NOTE";
            case 8: return "NOBITS";
            case 9: return "REL";
            case 10: return "SHLIB";
            case 11: return "DYNSYM";
            case 14: return "INIT_ARRAY";
            case 15: return "FINI_ARRAY";
            case 16: return "PREINIT_ARRAY";
            case 17: return "GROUP";
            case 18: return "SYMTAB_SHNDX";
            default:
                if (sh_type >= 0x60000000 && sh_type <= 0x6fffffff) return "OS_SPECIFIC";
                if (sh_type >= 0x70000000 && sh_type <= 0x7fffffff) return "PROC_SPECIFIC";
                if (sh_type >= 0x80000000) return "USER_DEFINED";
                return "UNKNOWN";
        }
    }
    //get section by name
    std::tuple<uint64_t, uint64_t, uint64_t> getSect(const std::string& name) const {
        return std::visit([&](auto&& hdr) -> std::tuple<uint64_t, uint64_t, uint64_t> {
            using HdrT = std::decay_t<decltype(hdr)>;
            using ShdrT = std::conditional_t<std::is_same_v<HdrT, Elf64_Ehdr>, Elf64_Shdr, Elf32_Shdr>;

            for (int i = 0; i < hdr.e_shnum; ++i) {
                ShdrT sh{};
                fseek(file, hdr.e_shoff + i * hdr.e_shentsize, SEEK_SET);
                fread(&sh, 1, sizeof(sh), file);

                long shstr_offset = hdr.e_shoff + hdr.e_shstrndx * hdr.e_shentsize;
                ShdrT shstr{};
                fseek(file, shstr_offset, SEEK_SET);
                fread(&shstr, 1, sizeof(shstr), file);

                std::vector<char> shstrtab(shstr.sh_size);
                fseek(file, shstr.sh_offset, SEEK_SET);
                fread(shstrtab.data(), 1, shstrtab.size(), file);

                std::string secName = (sh.sh_name < shstrtab.size()) ? &shstrtab[sh.sh_name] : "<noname>";

                if (secName == name) {
                    return {sh.sh_offset, sh.sh_size, sh.sh_entsize};
                }
            }
            throw std::runtime_error("Section " + name + " not found.");
        }, header);
    }
    //make symbols more readable
    static std::string demangle(const char* name) {
        int status = 0;
        std::unique_ptr<char, void(*)(void*)> result{
            abi::__cxa_demangle(name, nullptr, nullptr, &status),
            std::free
        };
        return (status == 0) ? result.get() : name;
    }
};

#endif // ELF_H
