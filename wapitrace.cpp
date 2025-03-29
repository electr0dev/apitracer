#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

void AnalyzePE(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Dosya açılamadı: " << filePath << std::endl;
        return;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        std::cerr << "Dosya okunamadı: " << filePath << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Geçersiz PE dosyası: " << filePath << std::endl;
        return;
    }

    PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Geçersiz PE dosyası: " << filePath << std::endl;
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        ImageRvaToVa(ntHeaders, buffer.data(), ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nullptr));

    if (!importDescriptor) {
        std::cerr << "Import tablosu bulunamadı: " << filePath << std::endl;
        return;
    }

    while (importDescriptor->Name) {
        const char* dllName = reinterpret_cast<const char*>(ImageRvaToVa(ntHeaders, buffer.data(), importDescriptor->Name, nullptr));
        std::cout << "DLL: " << dllName << std::endl;

        PIMAGE_THUNK_DATA64 thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(ImageRvaToVa(ntHeaders, buffer.data(), importDescriptor->OriginalFirstThunk, nullptr));
        while (thunk->u1.AddressOfData) {
            if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                std::cout << "  API: Ordinal " << (thunk->u1.Ordinal & 0xFFFF) << std::endl;
            }
            else {
                PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(ImageRvaToVa(ntHeaders, buffer.data(), thunk->u1.AddressOfData, nullptr));
                std::cout << "  API: " << importByName->Name << std::endl;
            }
            thunk++;
        }

        importDescriptor++;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "electr0dev:)\n" << "API Tracing Toolkit v1.0";
        std::cerr << "\n\nKullanim: " << argv[0] << " <dosya yolu>" << std::endl;
        return 1;
    }

    std::string filePath = argv[1];
    AnalyzePE(filePath);

    return 0;
}