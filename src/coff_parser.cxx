/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#include "coff_parser.h"
#include <minwindef.h>
#include <cstdio>
#include "coff.h"
#include "coff_pe_reporter.h"
#include "coff_reader_writer.h"
#include "utils.h"

#include <winnt.h>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <iosfwd>
#include <iostream>
#include <string>
#include <vector>

using CoffMembers = std::vector<coff_entry>;

CoffParser::CoffParser(CoffReaderWriter* coff_reader)
    : coffStream_(coff_reader) {}

/**
 * Parses a COFF file from a file stream from an opened file
 * 
 * Performs validation of the correct type and structure of the file
 * by verifying it has a COFF archive signature and is correctly structured
 * and then reads in the file, member by member, and parses the archive header and
 * member utilizing the appropriate scheme (as determine by the COFF scheme) and stores
 * the parsed information in the coffparser object.
 * 
 * This method sets CoffParser's "verified" attribute, which indicates we've successfully
 * identified the type of library. True if we were able to determine library type, false if not
 * 
 * \return True if the file we're parsing is a legitimate import library
 * False if its anything else or we've encountered an error/unexpectedly structured data
 */
bool CoffParser::Parse() {
    if (!this->coffStream_->Open()) {
        std::cerr << "Unable to open coff file for reading: "
                  << reportLastError() << "\n";
        return false;
    }
    int const invalid_valid_sig =
        static_cast<int>(this->coffStream_->ReadSig(this->coff_));
    if (invalid_valid_sig) {
        std::cerr << "Invalid signature for expected COFF archive format file: "
                  << this->coffStream_->get_file() << "\n";
        return false;
    }
    CoffMembers members;
    while (!(this->coffStream_->peek() == EOF)) {
        auto* header = new IMAGE_ARCHIVE_MEMBER_HEADER;
        auto* member = new coff_member;
        std::streampos const offset = this->coffStream_->tell();
        this->coffStream_->ReadHeader(header);
        this->coffStream_->ReadMember(header, member);
        if (!this->ParseData(header, member)) {
            this->verified_ = true;
            return false;
        }
        coff_entry entry;
        entry.header = header;
        entry.member = member;
        entry.offset = offset;
        members.emplace_back(entry);
    }
    // validate end of file
    if (!this->coffStream_->end()) {
        std::cerr << "Unexpected end of file encountered. Please ensure input "
                     "file is not corrupted\n";
        return false;
    }
    this->coff_.members = members;
    this->coffStream_->clear();
    return true;
}

int CoffParser::Verify() {
    bool const parse_status = this->Parse();
    if (!parse_status && !this->verified_) {
        // actual error in parsing the library
        return 2;
    }
    if (!parse_status && this->verified_) {
        // library is valid, it's just a static
        // lib, not an import
        return 1;
    }
    // otherwise, successful, it's an import lib
    return 0;
}

/**
 * Parses a member section in the form of a short format import section
 *  based on the COFF structure scheme
 *
 *  \param member A pointer to the member data to be parsed 
 */
void CoffParser::ParseShortImport(coff_member* member) {
    auto* im_h = reinterpret_cast<IMPORT_OBJECT_HEADER*>(member->data);
    // validate header
    if (!(im_h->Sig1 == 0x00) || !(im_h->Sig2 == 0xFFFF)) {
        return;
    }
    auto* short_member = new short_import_member();
    short_member->im_h = im_h;
    short_member->short_name = reinterpret_cast<char*>(im_h + 1);
    short_member->short_dll =
        short_member->short_name + strlen(short_member->short_name) + 1;
    member->short_member = short_member;
    member->is_short = true;
}

/**
 * Parses a member section in the form of a fully qualified import section
 *  based on the COFF structure scheme
 *
 *  \param member A pointer to the member data to be parsed 
 */
void CoffParser::ParseFullImport(coff_member* member) {
    // Parse image file header
    auto* file_h = reinterpret_cast<PIMAGE_FILE_HEADER>(member->data);
    // Parse section headers
    auto* p_sections = new IMAGE_SECTION_HEADER[file_h->NumberOfSections];
    for (int i = 0; i < file_h->NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER const sec_h =
            *reinterpret_cast<PIMAGE_SECTION_HEADER>(
                member->data + sizeof(IMAGE_FILE_HEADER) +
                (sizeof(IMAGE_SECTION_HEADER) * i));
        *(p_sections + i) = sec_h;
    }
    // Parse section data
    char** section_data = new char*[file_h->NumberOfSections];
    for (int i = 0; i < file_h->NumberOfSections; ++i) {
        DWORD const data_loc = (p_sections + i)->PointerToRawData;
        *(section_data + i) = member->data + data_loc;
    }
    // Parse Coff Symbol table
    PIMAGE_SYMBOL symbol_table = new IMAGE_SYMBOL[file_h->NumberOfSymbols];
    DWORD const symbol_table_offset = file_h->PointerToSymbolTable;
    for (int i = 0; i < file_h->NumberOfSymbols; ++i) {
        IMAGE_SYMBOL const im_sym = *reinterpret_cast<PIMAGE_SYMBOL>(
            member->data + symbol_table_offset + (sizeof(IMAGE_SYMBOL) * i));
        *(symbol_table + i) = im_sym;
    }
    // Parse string table
    DWORD const string_table_offset =
        symbol_table_offset + (sizeof(IMAGE_SYMBOL) * file_h->NumberOfSymbols);
    // first four bytes of string table give size of string table
    DWORD const size_of_string_table =
        *reinterpret_cast<PDWORD>(member->data + string_table_offset);
    char* string_table;
    if (size_of_string_table > 4) {
        // string table size bytes are included in the total size count for the
        // string table
        string_table = member->data + string_table_offset + sizeof(DWORD);
    }
    // We're done reading a given member's data field
    auto* long_member = new long_import_member;
    long_member->pfile_h = file_h;
    long_member->pp_sections = p_sections;
    long_member->section_data = section_data;
    long_member->symbol_table = symbol_table;
    long_member->string_table = string_table;
    long_member->size_of_string_table = size_of_string_table;
    long_member->string_table_offset = string_table_offset;
    member->long_member = long_member;
}

/**
 * Parses a member section of the structure of the first linker member
 *  based on the MS COFF structure scheme
 * 
 * \param member A pointer to the member data
 */
void CoffParser::ParseFirstLinkerMember(coff_member* member) {
    DWORD sym_count = *reinterpret_cast<PDWORD>(member->data);
    // Offsets are offset in member data by the sym count entry
    // which is a 4 byte value (DWORD)
    auto* poffsets = reinterpret_cast<PDWORD>(member->data + sizeof(DWORD));
    // symbol count is big endian in coff files but Windows is little endian
    sym_count = ToLittleEndian(sym_count);
    // string table of symbol names comes after symbol count and
    // the offsets so its offset is the sym size DWORD and the number
    // of symbols (from the first entry) * the 4 byte member header offsets (DWORD)
    char* pnames = member->data + sizeof(DWORD) + (sizeof(DWORD) * sym_count);
    auto* first_linker = new first_linker_member;
    first_linker->offsets = poffsets;
    first_linker->symbols = sym_count;
    first_linker->strings = pnames;
    member->first_link = first_linker;
}

/**
 * Parses a member section of the structure of the second linker member
 *  based on the MS COFF structure scheme
 * 
 * \param member A pointer to the member data
 */
void CoffParser::ParseSecondLinkerMember(coff_member* member) {
    // Second linker member member count is little endian already
    DWORD const archive_member_count = *reinterpret_cast<PDWORD>(member->data);
    auto* poffsets = reinterpret_cast<PDWORD>(member->data + sizeof(DWORD));
    DWORD const sym_count = *(reinterpret_cast<PDWORD>(
        member->data + (archive_member_count * sizeof(DWORD) + sizeof(DWORD))));
    auto* pindex =
        reinterpret_cast<PWORD>(member->data + (2 * sizeof(DWORD)) +
                                (archive_member_count * sizeof(DWORD)));
    char* names = reinterpret_cast<char*>(pindex) + (sym_count * sizeof(WORD));
    auto* second_linker = new second_linker_member;
    second_linker->members = archive_member_count;
    second_linker->offsets = poffsets;
    second_linker->symbols = sym_count;
    second_linker->indicies = pindex;
    second_linker->strings = names;
    member->second_link = second_linker;
}

namespace {
bool nameCheck(BYTE* name) {
    int const name_len = get_slash_name_length(reinterpret_cast<char*>(name));
    return findstr(reinterpret_cast<char*>(name), ".obj", name_len) == nullptr;
}
}  // namespace

/**
 * Drive the parsing of the "data" section of an import library member
 * 
 * Members are composed of the archive header, and a "data" section, which
 * is formatted differently depending on which member it is. The data section
 * comprises the significant portion of the "member" and is often referred to as
 * the "member" itself, despite the member being both the header and data (member) section
 * 
 * Determines, based on the name of the archive header and the structure of the data/member seciton
 * which type of member it is and dispatches to the appropriate member method of the COFF parser class
 * 
 * \param header A pointer to the archive member header corresponding to the member being parsed
 * \param member A pointer to the member data being parsed
 * \return True if data indicates an import library, False if the archive is a static library
 */
bool CoffParser::ParseData(PIMAGE_ARCHIVE_MEMBER_HEADER header,
                           coff_member* member) {
    auto* p_imp_header = reinterpret_cast<IMPORT_OBJECT_HEADER*>(member->data);
    if ((p_imp_header->Sig1 == IMAGE_FILE_MACHINE_UNKNOWN) &&
        (p_imp_header->Sig2 == IMPORT_OBJECT_HDR_SIG2)) {
        // SHORT IMPORT LIB FORMAT (NT4,SP3)
        CoffParser::ParseShortImport(member);
    } else if (!strncmp(reinterpret_cast<char*>(header->Name),
                        IMAGE_ARCHIVE_LINKER_MEMBER, 16)) {
        if (!nameCheck(header->Name)) {
            return false;
        }
        if (!this->coff_.read_first_linker) {
            CoffParser::ParseFirstLinkerMember(member);
            this->coff_.read_first_linker = true;
        } else {
            CoffParser::ParseSecondLinkerMember(member);
        }
    } else if (!strncmp(reinterpret_cast<char*>(header->Name),
                        IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16)) {
        // Check the long names member for values, if so, check the extension has a dll
        if (!CoffParser::ValidateLongName(
                member, atoi(reinterpret_cast<char*>(header->Size)))) {
            return false;
        }
        member->is_longname = true;
    } else {
        if (!nameCheck(header->Name)) {
            return false;
        }
        CoffParser::ParseFullImport(member);
    }
    return true;
}

bool CoffParser::ValidateLongName(coff_member* member, int size) {
    if (!member->data) {
        // If we have no member, by virtue of correctly processing
        // the header to get to this point
        // we have a valid header
        return true;
    }
    // If a name has an object file, this is not an import
    // member
    char* obj_res = findstr(member->data, ".obj", size);
    return obj_res == nullptr;
}

void CoffParser::NormalizeLinkerMember(const std::string& name,
                                       const size_t& offset,
                                       const size_t& base_offset,
                                       const char* strings,
                                       const DWORD symbols) {
    unsigned long long const offset_with_header =
        base_offset + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
    size_t current_relative_offset = 0;
    for (int j = 0; j < symbols; ++j) {
        size_t const name_len = strlen(strings + current_relative_offset);
        char* new_name = new char[name_len + 1];
        strcpy(new_name, strings + current_relative_offset);
        if (strstr(new_name, name.c_str())) {
            replace_special_characters(new_name, name_len);
            unsigned long long const foffset =
                offset_with_header + offset + current_relative_offset;
            this->coffStream_->seek(0);
            this->coffStream_->seek(static_cast<long long>(foffset));
            this->coffStream_->write(new_name,
                                     static_cast<long long>(name_len));
        }
        current_relative_offset += name_len + 1;
        delete new_name;
    }
}

void CoffParser::NormalizeSectionNames(const std::string& name, char* section,
                                       const DWORD& section_data_start_offset,
                                       size_t data_size) {
    size_t const name_len = name.size();
    char* section_search_start = section;
    char* search_terminator = section + data_size;
    ptrdiff_t offset = 0;
    while (section_search_start && (section_search_start < search_terminator)) {
        // findstr's final parameter takes the size of the search domain
        // data_size defines the entire section, if a name is found in a section
        // subsequent searches must take the offset of the located name into account
        // respective to the size of the search domain
        section_search_start =
            findstr(section_search_start, name.c_str(), data_size - offset);
        if (section_search_start) {
            // we found a name, rename
            offset = section_search_start - section;
            char* new_name = new char[name_len];
            strncpy(new_name, section_search_start, name_len);
            replace_special_characters(new_name, name_len);
            this->writeRename(new_name, name_len,
                              section_data_start_offset + offset);
            delete new_name;
            section_search_start += name_len + 1;
            offset = section_search_start - section;
        }
    }
}

void CoffParser::writeRename(char* name, const size_t size, const size_t loc) {
    this->coffStream_->seek(0);
    this->coffStream_->seek(loc);
    this->coffStream_->write(name, size);
}

bool CoffParser::matchesName(char* old_name, const std::string& new_name) {
    return strcmp(old_name, new_name.c_str()) == 0;
}

/**
 * Normalizes mangled DLL names that represent absolute paths in COFF
 * binary files
 * 
 *  import libraries produced by Spack on Windows contain absolute paths to their
 *  corresponding DLLs, but due to constraints imposed by the linker command line
 *  must contained mangled versions of those paths
 * 
 *  This method takes the in memory, parsed version of the import library in COFF format
 *  and, using the structure of the COFF format, identifies and renames each location in which
 *  a mangled DLL name would be found.
 * 
 * \param name the absolute path to a dll to be unmangled
 */
bool CoffParser::NormalizeName(std::string& name) {
    // The dll is found with and without an extenion, depending on the context of the location
    // i.e. in the section data, it can be found with both an extension and extensionless
    //  whereas in the symbol table or linker member strings, it's always found without an extension
    std::string const name_no_ext = strip(name, ".dll");
    // Flag allowing us to skip multiple attempts
    // to rename the long names member this name
    bool long_name_renamed = false;
    // Iterate through the parsed COFF members
    for (auto mem : this->coff_.members) {
        int i = 0;
        // import member names from spack are of the form "/n      " where n is their place
        // in the longnames member, other members are "/[/]        "
        // This allows us to determine if we're looking at an import member, and where the offset is
        // Non Spack no linker/longname members are of the form "    /name-of-dll"
        while (i < 16 && mem.header->Name[i] != ' ') {
            ++i;
        }
        std::string const name_ref =
            std::string(reinterpret_cast<char*>(mem.header->Name), i);
        if (!endswith(name_ref, "/")) {
            // We have an import member
            // Name is longer than 16 bytes, need to lookup name in longname offset
            int const longname_offset =
                std::stoi(name_ref.substr(1, std::string::npos));
            // Reconstruct name from location in longnames member
            size_t const long_name_len =
                strlen(this->coff_.members[2].member->data + longname_offset);
            // Longnames member is always the third member if it exists
            // We know it exists at this point due to the success of the conditional above
            char* long_name = new char[long_name_len + 1];
            strncpy(long_name,
                    this->coff_.members[2].member->data + longname_offset,
                    long_name_len + 1);
            if (CoffParser::matchesName(long_name, name) &&
                !long_name_renamed) {
                // If so, unmangle it
                replace_special_characters(long_name, long_name_len + 1);
                // offset of actual longname member
                int const offset =
                    std::streamoff(this->coff_.members[2].offset);
                this->writeRename(long_name, long_name_len + 1,
                                  offset + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) +
                                      longname_offset);
                long_name_renamed = true;
            }
            delete long_name;
            // Import member name has been renamed
            // Now we rename the other DLL references
            // Import members have two forms, long and short, check for short
            if (mem.member->is_short) {
                // short import members are simple and easily parsed, we have
                // direct access to the name we're looking for from the inital parsing pass
                size_t const name_len =
                    strlen(mem.member->short_member->short_dll);
                char* new_name = new char[name_len + 1];
                // unmangle it
                strcpy(new_name, mem.member->short_member->short_dll);
                replace_special_characters(new_name, name_len);
                // ensure it's the name we're looking to rename
                if (CoffParser::matchesName(mem.member->short_member->short_dll,
                                            name)) {
                    // Member offset in file
                    unsigned long long offset = std::streamoff(mem.offset);
                    // Member header offset
                    offset += sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
                    // Now need relative offset to dll name in member
                    // First entry in short import member is the import header
                    offset += sizeof(IMPORT_OBJECT_HEADER);
                    // Next is the symbol name, which is a null terminated string
                    // +1 to preserve the null terminator in the coff member
                    offset += strlen(mem.member->short_member->short_name) + 1;
                    this->writeRename(new_name, strlen(new_name), offset);
                }
                delete new_name;
            } else {
                // Rename standard import members
                // First perform the section data renames
                WORD const section_data_count =
                    mem.member->long_member->pfile_h->NumberOfSections;
                for (int j = 0; j < section_data_count; ++j) {
                    PIMAGE_SECTION_HEADER psec_header =
                        mem.member->long_member->pp_sections + j;
                    // Get section data size from corresponding section header
                    int data_size = psec_header->SizeOfRawData;
                    int const virtual_size = psec_header->Misc.VirtualSize;
                    // Determine section data padding size
                    if (virtual_size > data_size) {
                        data_size += (virtual_size - data_size);
                    }
                    // section start offset in file
                    DWORD const section_data_start_offset =
                        std::streamoff(mem.offset) +
                        sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) +
                        psec_header->PointerToRawData;
                    // section start is longmember section pointer + index
                    char* section =
                        *(mem.member->long_member->section_data + j);
                    this->NormalizeSectionNames(name_no_ext, section,
                                                section_data_start_offset,
                                                data_size);
                }
                // Section data rename is complete, now rename string table
                int const relative_string_table_start_offset =
                    std::streamoff(mem.offset) +
                    sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) +
                    mem.member->long_member->string_table_offset +
                    sizeof(DWORD);
                char* string_table_start;
                char* string_table = mem.member->long_member->string_table;
                int const symbol_count =
                    mem.member->long_member->pfile_h->NumberOfSymbols;
                PIMAGE_SYMBOL symbols = mem.member->long_member->symbol_table;
                for (int j = 0; j < symbol_count; ++j) {
                    PIMAGE_SYMBOL symbol = symbols + j;
                    if (symbol->N.Name.Short == 0) {
                        // name is longer than 8 bytes, it's a Spack name, search
                        DWORD const name_string_table_offset =
                            symbol->N.Name.Long - sizeof(DWORD);
                        string_table_start =
                            strstr((string_table + name_string_table_offset),
                                   name_no_ext.c_str());
                        if (string_table_start &&
                            (string_table_start <
                             string_table + mem.member->long_member
                                                ->size_of_string_table)) {
                            ptrdiff_t const offset =
                                string_table_start - string_table;
                            size_t const name_len = name_no_ext.size();
                            char* new_no_ext_name = new char[name_len];
                            strncpy(new_no_ext_name, string_table_start,
                                    name_len);
                            replace_special_characters(new_no_ext_name,
                                                       name_len);
                            this->writeRename(
                                new_no_ext_name, name_len,
                                relative_string_table_start_offset + offset);
                            delete new_no_ext_name;
                        }
                    }
                }
            }
        } else if (!strncmp(reinterpret_cast<char*>(mem.header->Name),
                            IMAGE_ARCHIVE_LINKER_MEMBER, 16)) {
            // This is the first linker member, utilize the structure of the member to locate the
            // symbols section and search the symbols for our mangled dll name.
            // if found, replace with the unmangled version
            unsigned long long const base_offset = std::streamoff(mem.offset);
            if (mem.member->first_link) {
                unsigned long long const member_offset =
                    sizeof(DWORD) +
                    (mem.member->first_link->symbols * sizeof(DWORD));
                this->NormalizeLinkerMember(name_no_ext, member_offset,
                                            base_offset,
                                            mem.member->first_link->strings,
                                            mem.member->first_link->symbols);
            } else {
                // rename second linker member names
                size_t const member_offset =
                    sizeof(DWORD) +
                    (sizeof(DWORD) * mem.member->second_link->members) +
                    sizeof(DWORD) +
                    (sizeof(WORD) * mem.member->second_link->symbols);
                this->NormalizeLinkerMember(name_no_ext, member_offset,
                                            base_offset,
                                            mem.member->second_link->strings,
                                            mem.member->second_link->symbols);
            }
        } else if (!strncmp(reinterpret_cast<char*>(mem.header->Name),
                            IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16)) {
            // This is the longnames member, if we wanted to rename it directly we'd have to search through the
            // entire thing, wereas if we iterate to the import members, their names will give us the offset of
            // their name in the longnames member, meaning this can be a constant time operation if performed from
            // another context
            continue;
        } else {
            // If it's not an archive member or a long names offset based name, its either something we don't recognize
            // or it's a non Spack derived import
            // TODO(john.parent): Optionally warn rather than always report to std error, for externals this
            // will create way too much noise
            std::cerr << "Unrecognized or non Spack based import member: "
                      << mem.header->Name << "\n";
        }
    }
    this->coffStream_->Close();
    return true;
}

void CoffParser::ReportLongImportMember(long_import_member* long_import) {
    reportFileHeader(long_import->pfile_h);
    reportCoffSections(long_import);
    reportCoffSymbols(long_import);
}

void CoffParser::ReportShortImportMember(short_import_member* short_import) {
    reportImportObjectHeader(short_import->im_h);
    std::cout << "  DLL: " << short_import->short_dll << "\n";
    std::cout << "  Name: " << short_import->short_name << "\n";
}

void CoffParser::ReportLongName(const char* data) {
    std::cout << "DLL: " << data << "\n";
}

void CoffParser::Report() {
    for (auto mem : this->coff_.members) {
        if (mem.member->is_longname) {
            CoffParser::ReportLongName(mem.member->data);
        }
    }
}

int CoffParser::Validate(std::string& coff) {
    CoffReaderWriter coff_reader(coff);
    CoffParser coffp(&coff_reader);
    return coffp.Verify();
}

/**
 * Reports information about parsed coff file
 * 
 */
bool reportCoff(CoffParser& coff) {
    if (!coff.Parse()) {
        return false;
    }
    coff.Report();
    return true;
}