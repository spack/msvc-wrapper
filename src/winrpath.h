/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <winnt.h>
#include <strsafe.h>

#include "utils.h"
#include "execute.h"

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
typedef struct long_import_member {
    long long string_table_offset;
    DWORD size_of_string_table;
    PIMAGE_FILE_HEADER pfile_h;
    PIMAGE_SECTION_HEADER pp_sections;
    PIMAGE_SYMBOL symbol_table;
    char ** section_data;
    char * string_table;
    ~long_import_member() {
        for (int i=0; i< this->pfile_h->NumberOfSections; ++i) {
            delete *(this->section_data+i);
        }
        delete this->symbol_table;
        delete this->section_data;
        delete this->pp_sections;
        if(this->string_table) {
            delete this->string_table;
        }
    }
} long_import_member;

/**
 * @brief
 */
typedef struct short_import_member {
    IMPORT_OBJECT_HEADER *im_h;
    char * short_name;
    char * short_dll;
} short_import_member;

/**
 * 
 */
typedef struct first_linker_member {
    DWORD symbols;
    PDWORD offsets;
    char * strings;
} first_linker_member;

/**
 * 
 */
typedef struct second_linker_member {
    DWORD members;
    DWORD symbols;
    PDWORD offsets;
    PWORD indicies;
    char * strings;
} second_linker_member;



/**
 * @brief coff member 
 */
typedef struct coff_member {
    char * data;
    short_import_member *short_member;
    long_import_member *long_member;
    first_linker_member *first_link;
    second_linker_member *second_link;
    bool is_short;
    coff_member() {
        this->is_short = false;
        this->first_link = NULL;
        this->second_link = NULL;
        this->short_member = NULL;
        this->long_member = NULL;
    }
    ~coff_member () {
        delete short_member;
        delete long_member;
        delete first_link;
        delete second_link;
        delete data;
    }
} coff_member;

/**
 * @brief
 */
typedef struct coff_entry {
    std::streampos offset;
    PIMAGE_ARCHIVE_MEMBER_HEADER header;
    coff_member * member;
} coff_entry;

/**
 * @brief
 */
typedef struct coff {
    char signature[IMAGE_ARCHIVE_START_SIZE];
    std::vector<coff_entry> members;
    bool read_first_linker;
    coff() {
        this->read_first_linker = false;
    }
} coff;


/**
 * @brief Encapsulates a stream for reading and writing to a coff object
 * 
 * Provides abstractions around many common istream stream operations
 * for simple manipulation of the underlying COFF stream by a parser.
 * 
 * Provides additional, coff specific method, to read in specific types of data
 * in a structured format, i.e. ReadHeader reads in exactly enough data to populate
 * a coff member archive header and the ReadMember method behaves similarly for archive
 * member data. 
 * 
 * This class is designed for use by a CoffParser class, which should use this class to navigate
 * around and read in the relevant COFF data into memory and then parse it as it sees fit.
 * 
 * This class also provides a writer interface for said parser to write data to the COFF file.
 * This is not structured and expects to recives a series of bytes to write into the COFF binary.
 */
class CoffReaderWriter {
private:
    std::fstream pe_stream;
    std::string _file;
public:
    CoffReaderWriter(std::string file);
    ~CoffReaderWriter() = default;
    bool Open();
    bool Close();
    bool IsOpen();
    bool IsClosed();
    void ReadHeader(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in);
    void ReadMember(PIMAGE_ARCHIVE_MEMBER_HEADER head, coff_member *coff_in);
    bool ReadSig(coff &coff_in);
    void write(char * in, int size);
    void read(char * out, int size);
    void seek(int bytes=-1, std::ios_base::seekdir way=std::ios_base::beg);
    int peek();
    void clear();
    std::string get_file();
    std::streampos tell();
    bool end();

};

class CoffParser {
private:
    CoffReaderWriter* coffStream;
    coff coff;
    void ParseData(PIMAGE_ARCHIVE_MEMBER_HEADER header, coff_member *member);
    void ParseShortImport(coff_member *member);
    void ParseFullImport(coff_member *member);
    void ParseFirstLinkerMember(coff_member *member);
    void ParseSecondLinkerMember(coff_member *member);
    void ReportLongImportMember(long_import_member *li);
    void ReportShortImportMember(short_import_member *si);
public:
    CoffParser(CoffReaderWriter * cr);
    ~CoffParser() = default;
    bool Parse();
    bool NormalizeName(std::string &name);
    void Report();
};

class LinkerInvocation {
public:
    LinkerInvocation(const std::string &linkLine);
    LinkerInvocation(const StrList &linkline);
    ~LinkerInvocation() = default;
    void Parse();
    bool IsExeLink();
    std::string get_name();
    std::string get_out();
    std::string get_mangled_out();
private:
    std::string line;
    StrList tokens;
    std::string name;
    std::string output;
    StrList libs;
    StrList objs;
    bool is_exe;
};


class LibRename {
public:
    LibRename(std::string pe, bool full, bool deploy, bool replace, bool report);
    int ExecuteRename();
    int ExecuteLibRename();
    int ExecutePERename();
    int ComputeDefFile();
    std::string ComputeRenameLink();
    std::string ComputeDefLine();

private:
    int FindDllAndRename(HANDLE &pe_in);
    bool SpackCheckForDll(const std::string &dll_path);
    int RenameDll(char* pos, const std::string &dll_path);
    ExecuteCommand def_executor;
    ExecuteCommand lib_executor;
    std::string pe;
    std::string name;
    std::string new_lib;
    std::string def_file;
    bool full;
    bool deploy;
    bool replace;
    bool is_exe;
    bool report;
};


int reportCoff(CoffParser &coff);
