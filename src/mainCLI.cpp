#include <iostream>
#include <filesystem>
#include <iomanip>
#include <string>
#include <vector>
#include "elf.h"

int main() {
    std::filesystem::path path;
    std::cout << "Digite o path: ";
    std::cin >> path;

    try {
        ElfStudio elf(path);

        std::cout << "Architecture: " << elf.getArch() << '\n';
        std::cout << "Type: " << elf.getType() << '\n';

        auto info = elf.getInfo();
        std::cout << "Entry Point: 0x" << std::hex << info.entryPoint << std::dec << '\n';
        std::cout << "Section Count: " << info.sectionHeaderCount << '\n';
        std::cout << "Program Header Count: " << info.programHeaderCount << "\n\n";

        // Sections
        std::cout << "Sections:\n";
        std::cout << "---------------------------------------------------------------\n";
        auto sections = elf.getSections();
        for (const auto& sec : sections) {
            std::cout << "Name: " << sec.name
                      << " | Addr: 0x" << std::hex << sec.address
                      << " | Offset: " << std::dec << sec.offset
                      << " | Size: " << sec.size
                      << " | Type: " << sec.type
                      << " | Entropy: " << std::fixed << std::setprecision(3) << sec.entropy
                      << '\n';
        }
        std::cout << "---------------------------------------------------------------\n";

        // Program Headers
        std::cout << "Program Headers:\n";
        std::cout << "---------------------------------------------------------------\n";
        auto programs = elf.getProgram();
        for (const auto& prog : programs) {
            std::cout << "Type: " << prog.type
                      << " | Offset: " << prog.offset
                      << " | VAddr: 0x" << std::hex << prog.vaddr
                      << " | PAddr: 0x" << prog.paddr
                      << " | FileSz: " << std::dec << prog.filesz
                      << " | MemSz: " << prog.memsz
                      << " | Flags: " << prog.flags
                      << " | Align: " << prog.align
                      << '\n';
        }
        std::cout << "---------------------------------------------------------------\n";

        // Export Table
        std::cout << "Export Table (EAT):\n";
        std::cout << "---------------------------------------------------------------\n";
        auto exports = elf.getEAT();
        for (const auto& ex : exports) {
            std::cout << "Name: " << ex.name
                      << " | Address: 0x" << std::hex << ex.address
                      << '\n';
        }
        if (exports.empty()) {
            std::cout << "(None)\n";
        }
        std::cout << "---------------------------------------------------------------\n";

        // Import Table
        std::cout << "Import Table (IAT):\n";
        std::cout << "---------------------------------------------------------------\n";
        auto imports = elf.getIAT();
        for (const auto& imp : imports) {
            std::cout << "Name: " << imp.name
                      << " | Offset: 0x" << std::hex << imp.offset
                      << '\n';
        }
        if (imports.empty()) {
            std::cout << "(None)\n";
        }
        //Strings
        std::cout << "---------------------------------------------------------------\n";
        std::cout << "Strings:";
            for (const auto name2 : elf.dumpStrings()) {
                std::cout << "Name: " << name2 << '\n';
            }
        std::cout << "---------------------------------------------------------------\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
