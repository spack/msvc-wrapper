/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <minwindef.h>
#include <strsafe.h>
#include <winnt.h>
#include <iosfwd>
#include <vector>

// Structs for holding coff/PE data
// winnt headers define a number of
// PE/COFF components as structs
// Here we define structs to hold and
// organize those system defined structs
// and define our own in the cases winnt
// misses some

/**
 * @brief
 */
using long_import_member = struct long_import_member {
    long long string_table_offset;
    DWORD size_of_string_table;
    PIMAGE_FILE_HEADER pfile_h;
    PIMAGE_SECTION_HEADER pp_sections;
    PIMAGE_SYMBOL symbol_table;
    char** section_data;
    char* string_table;

    ~long_import_member() {
        for (int i = 0; i < this->pfile_h->NumberOfSections; ++i) {
            delete *(this->section_data + i);
        }
        delete this->symbol_table;
        delete this->section_data;
        delete this->pp_sections;
        delete this->string_table;
    }
};

/**
 * @brief
 */
using short_import_member = struct short_import_member {
    IMPORT_OBJECT_HEADER* im_h;
    char* short_name;
    char* short_dll;
};

/**
 * 
 */
using first_linker_member = struct first_linker_member {
    DWORD symbols;
    PDWORD offsets;
    char* strings;
};

/**
 * 
 */
using second_linker_member = struct second_linker_member {
    DWORD members;
    DWORD symbols;
    PDWORD offsets;
    PWORD indicies;
    char* strings;
};

/**
 * @brief coff member 
 */
using coff_member = struct coff_member {
    char* data;
    short_import_member* short_member;
    long_import_member* long_member;
    first_linker_member* first_link;
    second_linker_member* second_link;
    bool is_short;
    bool is_longname;

    coff_member() {
        this->is_short = false;
        this->is_longname = false;
        this->first_link = nullptr;
        this->second_link = nullptr;
        this->short_member = nullptr;
        this->long_member = nullptr;
    }

    ~coff_member() {
        delete short_member;
        delete long_member;
        delete first_link;
        delete second_link;
        delete data;
    }
};

/**
 * @brief
 */
using coff_entry = struct coff_entry {
    std::streampos offset;
    PIMAGE_ARCHIVE_MEMBER_HEADER header;
    coff_member* member;
};

/**
 * @brief
 */
using coff = struct coff {
    char signature[IMAGE_ARCHIVE_START_SIZE];
    std::vector<coff_entry> members;
    bool read_first_linker;

    coff() { this->read_first_linker = false; }
};
