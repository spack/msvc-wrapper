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

#pragma pack(push, r1, 1)

/**
 * @brief
 */
typedef struct coff_member {
    char * data;
    bool is_short;
    short_import_member *short_member;
    long_import_member *long_member;
    first_linker_member *first_link;
    second_linker_member *second_link;
    coff_member() {
        is_short = false;
    }
    ~coff_member () {
        if (this->is_short) {
            delete short_member;
        }
        else {
            delete long_member;
        }
        delete first_link;
        delete second_link;
        delete data;
    }
} coff_member;

/**
 * @brief
 */
typedef struct long_import_member {
    PIMAGE_FILE_HEADER pfile_h;
    PIMAGE_SECTION_HEADER * pp_sections;
    char ** section_data;
    PIMAGE_SYMBOL * symbol_table;
    char * string_table;
    DWORD size_of_string_table;
    long long string_table_offset;
    ~long_import_member() {
        for (int i=0; i<this->pfile_h->NumberOfSymbols; ++i) {
            delete *(this->symbol_table+i);
        }
        for (int i=0; i< this->pfile_h->NumberOfSections; ++i) {
            delete *(this->section_data+i);
            delete *(this->pp_sections+i);
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
    char * short_name;
    char * short_dll;
    IMPORT_OBJECT_HEADER *im_h;
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
    PDWORD offsets;
    DWORD symbols;
    PWORD indicies;
    char * strings;
} second_linker_member;

/**
 * 
 */
typedef struct longnames_member {
    char * names_field;
} longnames_member;

/**
 * @brief
 */
typedef struct coff_entry {
    std::streampos offset;
    PIMAGE_ARCHIVE_MEMBER_HEADER header;
    coff_member member;
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

#pragma pack(pop, r1)


/**
 * @brief Encapsulates a stream reading a COFF file object
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
    bool isOpen();
    bool isClosed();
    void read_header(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in);
    void read_member(PIMAGE_ARCHIVE_MEMBER_HEADER head, coff_member &coff_in);
    bool read_sig(coff &coff_in);
    void write(char * in, int size);
    void read(char * out, int size);
    void seek(int bytes=-1, std::ios_base::seekdir way=std::ios_base::beg);
    void clear();
    std::string get_file();
    std::streampos tell();
    bool end();

};

class CoffParser {
private:
    CoffReaderWriter* coffStream;
    coff coff_;
    void parse_data(PIMAGE_ARCHIVE_MEMBER_HEADER header, coff_member &member);
    void parse_short_import(coff_member &member);
    void parse_full_import(coff_member &member);
    void parse_first_linker_member(coff_member &member);
    void parse_second_linker_member(coff_member &member);
    int compute_section_data_offset(int section_number, long_import_member *mem);
public:
    CoffParser(CoffReaderWriter * cr);
    ~CoffParser() = default;
    bool parse();
    bool normalize_name(std::string &name);
};

class LinkerInvocation {
public:
    LinkerInvocation(const std::string &linkLine);
    LinkerInvocation(const StrList &linkline);
    ~LinkerInvocation() = default;
    void parse();
    bool is_exe_link();
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
    LibRename(std::string pe, bool full, bool deploy, bool replace);
    int executeRename();
    int executeLibRename();
    int executePERename();
    int computeDefFile();
    std::string compute_rename_line();
    std::string compute_def_line();

private:
    int find_dll_and_rename(HANDLE &pe_in);
    bool spack_check_for_dll(const std::string &dll_name);
    int rename_dll(DWORD pos, const std::string &new_name);
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
};
