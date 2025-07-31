/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include "winrpath.h"

/**
 * Takes a coff header struct and displays it to the terminal
 */
void reportArchiveHeader(const PIMAGE_ARCHIVE_MEMBER_HEADER header) {
    printf("----------------------------------\n");
    printf("  Name:    %.16s\n", header->Name);
    printf("  Date:    %.16s\n", header->Date);
    printf("  User ID: %.6s\n", header->UserID);
    printf("  Group ID:  %.6s\n", header->GroupID);
    printf("  Mode:     %.6s\n", header->Mode);
    printf("  Size:     %.12s\n", header->Size);
}

void reportFileHeader(const PIMAGE_FILE_HEADER pfile_h) {
    printf("------------------------------------\n");
    printf("  Machine:    %.16s\n", pfile_h->Machine);
    printf("  NumberOfSections    %.16s\n", pfile_h->NumberOfSections);
    printf("  TimeDateStamp    %.16s\n", pfile_h->TimeDateStamp);
    printf("  PointerToSymbolTable    %.16s\n", pfile_h->PointerToSymbolTable);
    printf("  NumberOfSymbols    %.16s\n", pfile_h->NumberOfSymbols);
    printf("  SizeOfOptionalHeader    %.16s\n", pfile_h->SizeOfOptionalHeader);
    printf("  Characteristics    %.16s\n", pfile_h->Characteristics);
}

void reportSectionHeader(const PIMAGE_SECTION_HEADER psection) {
    printf("  Name    %.16s\n", psection->Name);
    printf("  PhysicalAddress    %.16s\n", psection->Misc.PhysicalAddress);
    printf("  VirtualSize    %.16s\n", psection->Misc.VirtualSize);
    printf("  VirtualAddress    %.16s\n", psection->VirtualAddress);
    printf("  SizeOfRawData    %.16s\n", psection->SizeOfRawData);
    printf("  PointerToRawData    %.16s\n", psection->PointerToRawData);
    printf("  PointerToRelocations    %.16s\n", psection->PointerToRelocations);
    printf("  PointerToLineNumbers    %.16s\n", psection->PointerToLinenumbers);
    printf("  NumberOfRelocations    %.16s\n", psection->NumberOfRelocations);
    printf("  NumberOfLinenumbers    %.16s\n", psection->NumberOfLinenumbers);
    printf("  Characteristics    %.16s\n", psection->Characteristics);
}

void reportImageSymbol(const PIMAGE_SYMBOL psymbol) {
    printf("  LongName    %.16s\n", psymbol->N.LongName);
    printf("  ShortName    %.16s\n", psymbol->N.ShortName);
    printf("  Short    %.16s\n", psymbol->N.Name.Short);
    printf("  Long    %.16s\n", psymbol->N.Name.Long);
    printf("  Value    %.16s\n", psymbol->Value);
    printf("  SectionNumber    %.16s\n", psymbol->SectionNumber);
    printf("  Type    %.16s\n", psymbol->Type);
    printf("  StorageClass    %.16s\n", psymbol->StorageClass);
    printf("  NumberOfAuxSymbols    %.16s\n", psymbol->NumberOfAuxSymbols);
}

void reportImportObjectHeader(const IMPORT_OBJECT_HEADER* imp_h) {
    printf("  Sig1    %.16s\n", imp_h->Sig1);
    printf("  Sig2    %.16s\n", imp_h->Sig2);
    printf("  Version    %.16s\n", imp_h->Version);
    printf("  Machine    %.16s\n", imp_h->Machine);
    printf("  TimeDateStamp    %.16s\n", imp_h->TimeDateStamp);
    printf("  SizeOfData    %.16s\n", imp_h->SizeOfData);
    printf("  Type    %.16s\n", imp_h->Type);
    printf("  NameType    %.16s\n", imp_h->NameType);
    printf("  Reserved    %.16s\n", imp_h->Reserved);
    printf("  Ordinal    %.16s\n", imp_h->Ordinal);
    printf("  Hint    %.16s\n", imp_h->Hint);
}

void reportCoffSections(const long_import_member* mem) {
    for (int i = 0; i < mem->pfile_h->NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER head = mem->pp_sections + i;
        reportSectionHeader(head);
        int section_size = head->SizeOfRawData;
        int virtual_size = head->Misc.VirtualSize;
        if (virtual_size > section_size) {
            section_size += (virtual_size - section_size);
        }
        char* section = *(mem->section_data + i);
        printf("SECTION:\n");
        printf("%.*s\n", section_size, section);
    }
}

void reportCoffSymbols(const long_import_member* mem) {
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