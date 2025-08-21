/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <minwindef.h>
#include <winnt.h>
#include <cstdio>
#include "coff.h"

/**
 * Takes a coff header struct and displays it to the terminal
 */
inline void reportArchiveHeader(PIMAGE_ARCHIVE_MEMBER_HEADER header) {
    printf("----------------------------------\n");
    printf("  Name:    %.16s\n", header->Name);
    printf("  Date:    %.16s\n", header->Date);
    printf("  User ID: %.6s\n", header->UserID);
    printf("  Group ID:  %.6s\n", header->GroupID);
    printf("  Mode:     %.6s\n", header->Mode);
    printf("  Size:     %.12s\n", header->Size);
}

inline void reportFileHeader(PIMAGE_FILE_HEADER pfile_h) {
    printf("------------------------------------\n");
    printf("  Machine:    %.16X\n", pfile_h->Machine);
    printf("  NumberOfSections    %.1u\n", pfile_h->NumberOfSections);
    printf("  TimeDateStamp    %.16X\n", pfile_h->TimeDateStamp);
    printf("  PointerToSymbolTable    %.16X\n", pfile_h->PointerToSymbolTable);
    printf("  NumberOfSymbols    %.16X\n", pfile_h->NumberOfSymbols);
    printf("  SizeOfOptionalHeader    %.16u\n", pfile_h->SizeOfOptionalHeader);
    printf("  Characteristics    %.16X\n", pfile_h->Characteristics);
}

inline void reportSectionHeader(PIMAGE_SECTION_HEADER psection) {
    printf("  Name    %.16s\n", psection->Name);
    printf("  PhysicalAddress    %.16X\n", psection->Misc.PhysicalAddress);
    printf("  VirtualSize    %.16X\n", psection->Misc.VirtualSize);
    printf("  VirtualAddress    %.16X\n", psection->VirtualAddress);
    printf("  SizeOfRawData    %.16X\n", psection->SizeOfRawData);
    printf("  PointerToRawData    %.16X\n", psection->PointerToRawData);
    printf("  PointerToRelocations    %.16X\n", psection->PointerToRelocations);
    printf("  PointerToLineNumbers    %.16X\n", psection->PointerToLinenumbers);
    printf("  NumberOfRelocations    %.16u\n", psection->NumberOfRelocations);
    printf("  NumberOfLinenumbers    %.16u\n", psection->NumberOfLinenumbers);
    printf("  Characteristics    %.16X\n", psection->Characteristics);
}

inline void reportImageSymbol(PIMAGE_SYMBOL psymbol) {
    printf("  LongName    %.16s\n", (char*)psymbol->N.LongName);
    printf("  ShortName    %.16s\n", (char*)psymbol->N.ShortName);
    printf("  Short    %.16X\n", psymbol->N.Name.Short);
    printf("  Long    %.16X\n", psymbol->N.Name.Long);
    printf("  Value    %.16X\n", psymbol->Value);
    printf("  SectionNumber    %.16hd\n", psymbol->SectionNumber);
    printf("  Type    %.16u\n", psymbol->Type);
    printf("  StorageClass    %.16u\n", psymbol->StorageClass);
    printf("  NumberOfAuxSymbols    %.16u\n", psymbol->NumberOfAuxSymbols);
}

inline void reportImportObjectHeader(IMPORT_OBJECT_HEADER* imp_h) {
    printf("  Sig1    %.16u\n", imp_h->Sig1);
    printf("  Sig2    %.16u\n", imp_h->Sig2);
    printf("  Version    %.16u\n", imp_h->Version);
    printf("  Machine    %.16u\n", imp_h->Machine);
    printf("  TimeDateStamp    %.16X\n", imp_h->TimeDateStamp);
    printf("  SizeOfData    %.16X\n", imp_h->SizeOfData);
    printf("  Type    %.16u\n", imp_h->Type);
    printf("  NameType    %.16u\n", imp_h->NameType);
    printf("  Reserved    %.16u\n", imp_h->Reserved);
    printf("  Ordinal    %.16u\n", imp_h->Ordinal);
    printf("  Hint    %.16u\n", imp_h->Hint);
}

inline void reportCoffSections(const long_import_member* mem) {
    for (int i = 0; i < mem->pfile_h->NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER head = mem->pp_sections + i;
        reportSectionHeader(head);
        int section_size = head->SizeOfRawData;
        int const virtual_size = head->Misc.VirtualSize;
        if (virtual_size > section_size) {
            section_size += (virtual_size - section_size);
        }
        char* section = *(mem->section_data + i);
        printf("SECTION:\n");
        printf("%.*s\n", section_size, section);
    }
}

inline void reportCoffSymbols(const long_import_member* mem) {
    for (int i = 0; i < mem->pfile_h->NumberOfSymbols; ++i) {
        PIMAGE_SYMBOL sym = mem->symbol_table + i;
        reportImageSymbol(sym);
        DWORD name_string_table_offset;
        if (!sym->N.Name.Short) {
            name_string_table_offset = sym->N.Name.Long - sizeof(DWORD);
        } else {
            name_string_table_offset = sym->N.Name.Short - sizeof(DWORD);
        }
        printf("%.*s", mem->size_of_string_table,
               mem->string_table + name_string_table_offset);
    }
}