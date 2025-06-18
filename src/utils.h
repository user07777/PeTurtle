//
// Created by kaisy on 17-06-2025.
//

#ifndef UTILS_H
#define UTILS_H
#include <cstdint>
#include <string>
#define UNREFERENCED_PARAMETER(P) (void)(P)
struct ElfInfo {
    uint64_t entryPoint;
    uint64_t programHeaderOffset;
    uint64_t sectionHeaderOffset;
    uint32_t flags;
    uint16_t headerSize;
    uint16_t HeaderEntrySize;
    uint16_t programHeaderCount;
    uint16_t sectionHeaderEntrySize;
    uint16_t sectionHeaderCount;
    uint16_t sectionHeaderStringIndex;
};

struct Section {
    std::string name;
    uint64_t address;
    uint64_t offset;
    uint64_t size;
    std::string type;
    double entropy;
};

struct Program {
    std::string type;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    std::string flags;
    uint64_t align;
};
struct IAT {
    std::string name;
    uint64_t offset;
};

struct EAT {
    std::string name;
    uint64_t address;
};

#endif //UTILS_H
