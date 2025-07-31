/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once
#include "winrpath.h"
#include <fileapi.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <stdio.h>
#include <winnt.h>
#include <cstdio>
#include "coff_pe_reporter.h"
#include "execute.h"
#include "utils.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ios>
#include <iosfwd>
#include <iostream>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

using CoffMembers = std::vector<coff_entry>;

/**
 * Parses the command line of a given linker invocation and stores information
 * about that command line and its associated behavior
 */
LinkerInvocation::LinkerInvocation(std::string linkLine)
    : line(std::move(linkLine)), is_exe(true) {
    StrList const tokenized_line = split(this->line, " ");
    this->tokens = tokenized_line;
}

LinkerInvocation::LinkerInvocation(const StrList& linkLine) {
    this->tokens = linkLine;
    this->line = join(linkLine);
}

/**
 * Parses a linker invocation to extract imformation about the artifacts produced
 * and the obj files used to produce it
 */
void LinkerInvocation::Parse() {
    for (auto token = this->tokens.begin(); token != this->tokens.end();
         ++token) {
        std::string normal_token = *token;
        lower(normal_token);
        // implib specifies the eventuall import libraries name
        // and thus will contain a ".lib" extension, which
        // the next check will process as a library argument
        if (normal_token.find("implib:") != std::string::npos) {
            // If there was nothing after the ":", the
            // previous link command would have failed
            // and : is not a legal character in a name
            // guarantees this split command produces a vec of
            // len 2
            StrList implib_line = split(*token, ":");
            this->implibname = implib_line[1];
        } else if (endswith(normal_token, ".lib")) {
            this->libs.push_back(*token);
        } else if (normal_token == "/dll" || normal_token == "-dll") {
            this->is_exe = false;
        } else if (startswith(normal_token, "-out") ||
                   startswith(normal_token, "/out")) {
            this->output = split(*token, ":")[1];
        } else if (endswith(normal_token, ".obj")) {
            this->objs.push_back(*token);
        } else if (normal_token.find("def:") != std::string::npos) {
            StrList def_line = split(*token, ":");
            this->def_file = def_line[1];
        } else if (startswith(normal_token, "@") &&
                   endswith(normal_token, ".rsp")) {
            // RSP files are used to describe object files, libraries, other CLI
            // Switches relevant to the tool the rsp file is being passed to
            // Primarily utilized by CMake and MSBuild projects to bypass
            // Command line length limits
            this->rsp_file = *token;
        }
    }
    std::string const ext = this->is_exe ? ".exe" : ".dll";
    if (this->output.empty()) {
        this->output = strip(this->objs.front(), ".obj") + ext;
    }
    this->name = strip(this->output, ext);
    if (this->implibname.empty()) {
        this->implibname = this->name + ".lib";
    }
}

std::string LinkerInvocation::get_name() {
    return this->name;
}

std::string LinkerInvocation::get_implib_name() {
    return this->implibname;
}

std::string LinkerInvocation::get_def_file() {
    return this->def_file;
}

std::string LinkerInvocation::get_rsp_file() {
    return this->rsp_file;
}

std::string LinkerInvocation::get_out() {
    return this->output;
}

std::string LinkerInvocation::get_mangled_out() {
    return mangle_name(this->output);
}

bool LinkerInvocation::IsExeLink() {
    return this->is_exe || endswith(this->output, ".exe");
}

CoffReaderWriter::CoffReaderWriter(std::string file)
    : _file(std::move(std::move(file))) {}

bool CoffReaderWriter::Open() {
    this->pe_stream.open(this->_file,
                         std::ios::in | std::ios::out | std::ios::binary);
    return this->pe_stream.is_open();
}

bool CoffReaderWriter::Close() {
    this->pe_stream.close();
    return !this->pe_stream.is_open();
}

void CoffReaderWriter::clear() {
    this->pe_stream.clear();
}

bool CoffReaderWriter::IsOpen() {
    return this->pe_stream.is_open();
}

bool CoffReaderWriter::IsClosed() {
    return !this->pe_stream.is_open();
}

bool CoffReaderWriter::ReadSig(coff& coff_in) {
    this->pe_stream.read(reinterpret_cast<char*>(&coff_in.signature),
                         IMAGE_ARCHIVE_START_SIZE);
    return strcmp(coff_in.signature, IMAGE_ARCHIVE_START) != 0;
}

void CoffReaderWriter::ReadHeader(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in) {
    this->pe_stream.read(reinterpret_cast<char*>(coff_in),
                         sizeof(IMAGE_ARCHIVE_MEMBER_HEADER));
}

void CoffReaderWriter::ReadMember(PIMAGE_ARCHIVE_MEMBER_HEADER head,
                                  coff_member* coff_in) {
    int const member_size = atoi(reinterpret_cast<char*>(head->Size));
    coff_in->data = new char[member_size];
    this->pe_stream.read(coff_in->data, member_size);
    if (member_size % 2 != 0) {
        this->seek(1, std::ios_base::cur);
    }
}

std::string CoffReaderWriter::get_file() {
    return this->_file;
}

std::streampos CoffReaderWriter::tell() {
    return this->pe_stream.tellg();
}

void CoffReaderWriter::seek(int bytes, std::ios_base::seekdir way) {
    this->pe_stream.seekg(bytes, way);
}

int CoffReaderWriter::peek() {
    return this->pe_stream.peek();
}

bool CoffReaderWriter::end() {
    return this->pe_stream.eof();
}

void CoffReaderWriter::read(char* out, int size) {
    this->pe_stream.read(out, size);
}

void CoffReaderWriter::write(char* in, int size) {
    this->pe_stream.write(in, size);
}

/**
 * Flushes the CoffReaderWriter's underlying stream to disk
 * 
 * This is primarily useful in debuging to ensure immediate
 * writes to disk rather than waiting for the buffer to overflow
 * so that operations performed on the coff file can be validated
 * in real time
 */
void CoffReaderWriter::flush() {
    this->pe_stream.flush();
}

CoffParser::CoffParser(CoffReaderWriter* cr) : coffStream(cr) {}

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
    if (!this->coffStream->Open()) {
        std::cerr << "Unable to open coff file for reading: "
                  << reportLastError() << "\n";
        return false;
    }
    int const invalid_valid_sig =
        static_cast<int>(this->coffStream->ReadSig(this->coff));
    if (invalid_valid_sig) {
        std::cerr << "Invalid signature for expected COFF archive format file: "
                  << this->coffStream->get_file() << "\n";
        return false;
    }
    CoffMembers members;
    while (!(this->coffStream->peek() == EOF)) {
        auto* header = new IMAGE_ARCHIVE_MEMBER_HEADER;
        auto* member = new coff_member;
        std::streampos const offset = this->coffStream->tell();
        this->coffStream->ReadHeader(header);
        this->coffStream->ReadMember(header, member);
        if (!this->ParseData(header, member)) {
            this->verified = true;
            return false;
        }
        coff_entry entry;
        entry.header = header;
        entry.member = member;
        entry.offset = offset;
        members.emplace_back(entry);
    }
    // validate end of file
    if (!this->coffStream->end()) {
        std::cerr << "Unexpected end of file encountered. Please ensure input "
                     "file is not corrupted\n";
        return false;
    }
    this->coff.members = members;
    this->coffStream->clear();
    return true;
}

int CoffParser::Verify() {
    bool const parse_status = this->Parse();
    if (!parse_status && !this->verified) {
        // actual error in parsing the library
        return 2;
    }
    if (!parse_status && this->verified) {
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
    auto* sm = new short_import_member();
    sm->im_h = im_h;
    sm->short_name = reinterpret_cast<char*>(im_h + 1);
    sm->short_dll = sm->short_name + strlen(sm->short_name) + 1;
    member->short_member = sm;
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
        int const data_loc = (p_sections + i)->PointerToRawData;
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
    auto* lm = new long_import_member;
    lm->pfile_h = file_h;
    lm->pp_sections = p_sections;
    lm->section_data = section_data;
    lm->symbol_table = symbol_table;
    lm->string_table = string_table;
    lm->size_of_string_table = size_of_string_table;
    lm->string_table_offset = string_table_offset;
    member->long_member = lm;
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
    auto* fl = new first_linker_member;
    fl->offsets = poffsets;
    fl->symbols = sym_count;
    fl->strings = pnames;
    member->first_link = fl;
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
    auto* sl = new second_linker_member;
    sl->members = archive_member_count;
    sl->offsets = poffsets;
    sl->symbols = sym_count;
    sl->indicies = pindex;
    sl->strings = names;
    member->second_link = sl;
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
        if (!this->coff.read_first_linker) {
            CoffParser::ParseFirstLinkerMember(member);
            this->coff.read_first_linker = true;
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
                                       const int& offset,
                                       const int& base_offset,
                                       const char* strings,
                                       const DWORD symbols) {
    int const offset_with_header =
        base_offset + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
    int current_relative_offset = 0;
    for (int j = 0; j < symbols; ++j) {
        int const name_len = strlen(strings + current_relative_offset);
        char* new_name = new char[name_len + 1];
        strcpy(new_name, strings + current_relative_offset);
        if (strstr(new_name, name.c_str())) {
            replace_special_characters(new_name, name_len);
            int const foffset =
                offset_with_header + offset + current_relative_offset;
            this->coffStream->seek(0);
            this->coffStream->seek(foffset);
            this->coffStream->write(new_name, name_len);
        }
        current_relative_offset += name_len + 1;
        delete new_name;
    }
}

void CoffParser::NormalizeSectionNames(const std::string& name, char* section,
                                       const DWORD& section_data_start_offset,
                                       int data_size) {
    int const name_len = name.size();
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

void CoffParser::writeRename(char* name, const int size, const int loc) {
    this->coffStream->seek(0);
    this->coffStream->seek(loc);
    this->coffStream->write(name, size);
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
    for (auto mem : this->coff.members) {
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
            int const long_name_len =
                strlen(this->coff.members[2].member->data + longname_offset);
            // Longnames member is always the third member if it exists
            // We know it exists at this point due to the success of the conditional above
            char* long_name = new char[long_name_len + 1];
            strncpy(long_name,
                    this->coff.members[2].member->data + longname_offset,
                    long_name_len + 1);
            if (CoffParser::matchesName(long_name, name) &&
                !long_name_renamed) {
                // If so, unmangle it
                replace_special_characters(long_name, long_name_len + 1);
                // offset of actual longname member
                int const offset = std::streamoff(this->coff.members[2].offset);
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
                int const name_len =
                    strlen(mem.member->short_member->short_dll);
                char* new_name = new char[name_len + 1];
                // unmangle it
                strcpy(new_name, mem.member->short_member->short_dll);
                replace_special_characters(new_name, name_len);
                // ensure it's the name we're looking to rename
                if (CoffParser::matchesName(mem.member->short_member->short_dll,
                                            name)) {
                    // Member offset in file
                    int offset = std::streamoff(mem.offset);
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
                            int const name_len = name_no_ext.size();
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
            int const base_offset = std::streamoff(mem.offset);
            if (mem.member->first_link) {
                int const member_offset =
                    sizeof(DWORD) +
                    (mem.member->first_link->symbols * sizeof(DWORD));
                this->NormalizeLinkerMember(name_no_ext, member_offset,
                                            base_offset,
                                            mem.member->first_link->strings,
                                            mem.member->first_link->symbols);
            } else {
                // rename second linker member names
                int const member_offset =
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
    this->coffStream->Close();
    return true;
}

void CoffParser::ReportLongImportMember(long_import_member* li) {
    reportFileHeader(li->pfile_h);
    reportCoffSections(li);
    reportCoffSymbols(li);
}

void CoffParser::ReportShortImportMember(short_import_member* si) {
    reportImportObjectHeader(si->im_h);
    std::cout << "  DLL: " << si->short_dll << "\n";
    std::cout << "  Name: " << si->short_name << "\n";
}

void CoffParser::ReportLongName(char* data) {
    std::cout << "DLL: " << data << "\n";
}

void CoffParser::Report() {
    for (auto mem : this->coff.members) {
        if (mem.member->is_longname) {
            CoffParser::ReportLongName(mem.member->data);
        }
    }
}

int CoffParser::Validate(std::string& coff) {
    CoffReaderWriter cr(coff);
    CoffParser coffp(&cr);
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

/*
 * Checks a DLL name for special characters, if we're deploying, a path character, if we're
 * relocating a spack sigil
 * 
 *  Path characters are not typically found in DLLs outside of those produced by this compiler wrapper
 *  and as such are an indication this is a Spack produced binary
 * 
 *  Spack sigils will not be found anywhere but a Spack produced binary as well
 * 
 * \param name The dll name to check for sigils or special path characters
 * 
*/
bool LibRename::SpackCheckForDll(const std::string& name) const {
    if (this->deploy) {
        return hasPathCharacters(name);
    }
    // First check for the case we're relocating out of a buildcache
    bool reloc_spack = false;
    if (!(name.find("<!spack>") == std::string::npos) ||
        !(name.find("<sp>") == std::string::npos)) {
        reloc_spack = true;
    }
    // If not, maybe we're just relocating a binary on the same system
    if (!reloc_spack) {
        reloc_spack = hasPathCharacters(name);
    }
    return reloc_spack;
}

/*
 * Actually performs the DLL rename, given the DLL location in mapped memory view
 * determines the required padding for a name, if deploying, the proper length of a sigil
 * then either writes the sigil'd name back into the memory map, or gets the new path to a dll
 * re-pads it, and then writes that into the DLL name location.
 * 
 * \param  name_loc Raw offset to the imported DLL name
 * \param dll_name The dll, in the case we're doing an extraction from the buildcache
 *                  that we'll look for a version of on the current system and rename
 *                  the dll name found at `name_loc` to the absolute path of
 * 
*/
bool LibRename::RenameDll(char* name_loc, const std::string& dll_path) const {
    if (this->deploy) {
        int const padding_len = get_padding_length(dll_path);
        if (padding_len < 8) {
            // path is too long to mark as a Spack path
            // use shorter sigil
            char short_sigil[] = "<sp>";
            // use _snprintf as it does not null terminate and we're writing into the middle
            // of a null terminated string we want to later read from properly
            _snprintf(name_loc, sizeof(short_sigil) - 1, "%s", short_sigil);
        } else {
            char long_sigil[] = "<!spack>";
            // See _snprintf comment above for use context
            _snprintf(name_loc, sizeof(long_sigil) - 1, "%s", long_sigil);
        }
    } else {
        std::string const file_name = basename(dll_path);
        if (file_name.empty()) {
            std::cerr << "Unable to extract filename from dll for relocation"
                      << "\n";
            return false;
        }
        LibraryFinder lf;
        std::string const new_library_loc = lf.FindLibrary(file_name, dll_path);
        if (new_library_loc.empty()) {
            std::cerr << "Unable to find library " << file_name << " at "
                      << dll_path << " for relocation" << "\n";
            return false;
        }
        char* new_lib =
            pad_path(new_library_loc.c_str(), new_library_loc.size());

        replace_special_characters(new_lib, MAX_NAME_LEN);

        // c_str returns a proper (i.e. null terminated) value, so we dont need to worry about
        // size differences w.r.t the path to the new library
        snprintf(name_loc, MAX_NAME_LEN + 1, "%s", new_lib);
    }
    return true;
}

/*
 * Loads DLL into memory the way it would be if loaded by the system
 * This is require behavior as the MSVC structs designed to parse the PE
 * format expect proper page/memory alignment, which is only done if properly
 * mapped into memory.
 * 
 * Decompose the PE file into a series of structs to locate the IMPORT section
 * Parse the IMPORT section for the names of all imported DLLS
 * If a given DLL name is a Spack derived DLL name, identifiable via the
 * spack sigil or the fact there are path characters in the DLL name, which is not 
 * normally the case without Spack, depending on the operation, the name is modified
 * If we're performing a deployment to a buildcache, we mark the name with a spack sigil
 * to identify it as one in need of relocation post builcache extraction
 * On extraction, we find dll names with the Spack sigil and rename (and repad) them with
 * the correct absolute path to the requisite DLL on the new host system.
 * 
 * This approach is heavily based on https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++#first-dll-name
 * 
 * \param pe_in the PE file for which to perform the imported DLL rename procedure
 * 
 * 
*/
bool LibRename::FindDllAndRename(HANDLE& pe_in) {
    HANDLE h_map_object =
        CreateFileMapping(pe_in, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (!h_map_object) {
        std::cerr << "Unable to create mapping object: " << reportLastError()
                  << "\n";
        return false;
    }
    LPVOID basepointer = static_cast<char*>(
        MapViewOfFile(h_map_object, FILE_MAP_WRITE, 0, 0, 0));
    if (!basepointer) {
        std::cerr << "Unable to create file map view\n";
        return false;
    }
    // Establish base PE headers
    auto* dos_header = static_cast<PIMAGE_DOS_HEADER>(basepointer);
    auto* nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(
        static_cast<char*>(basepointer) + dos_header->e_lfanew);

    auto* coff_header = reinterpret_cast<PIMAGE_FILE_HEADER>(
        static_cast<char*>(basepointer) + dos_header->e_lfanew +
        sizeof(nt_header->Signature));

    auto* optional_header = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(
        static_cast<char*>(basepointer) + dos_header->e_lfanew +
        sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader));

    auto* section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        static_cast<char*>(basepointer) + dos_header->e_lfanew +
        sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) +
        sizeof(nt_header->OptionalHeader));

    DWORD const number_of_rva_and_sections =
        optional_header->NumberOfRvaAndSizes;
    if (number_of_rva_and_sections == 0) {
        std::cerr << "PE file does not import symbols" << "\n";
        return false;
    }
    if (number_of_rva_and_sections < 2) {
        std::cerr << "PE file contains insufficient data directories, likely "
                     "corrupted"
                  << "\n";
        return false;
    }

    DWORD const number_of_sections = coff_header->NumberOfSections;
    // Data directory #2 points to the RVA of the import section
    DWORD const rva_import_directory =
        nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress;
    DWORD const import_section_file_offset = RvaToFileOffset(
        section_header, number_of_sections, rva_import_directory);
    char* import_table_offset =
        static_cast<char*>(basepointer) + import_section_file_offset;
    auto* import_image_descriptor =
        reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(import_table_offset);
    //DLL Imports
    for (; import_image_descriptor->Name != 0; import_image_descriptor++) {
        char* imported_dll =
            import_table_offset +
            (import_image_descriptor->Name - rva_import_directory);
        std::string const str_dll_name = std::string(imported_dll);
        if (this->SpackCheckForDll(str_dll_name)) {
            if (!this->RenameDll(imported_dll, str_dll_name)) {
                std::cerr << "Unable to relocate DLL reference: "
                          << str_dll_name << "\n";
                return false;
            }
        }
    }
    FlushViewOfFile((LPCVOID)basepointer, 0);
    UnmapViewOfFile((LPCVOID)basepointer);

    return SafeHandleCleanup(h_map_object) != 0;
}

/*
 * LibRename is responsible for renaming and relocating DLLs and
 * their corresponding import libraries
 * 
 * Deploy - this flag determines whether or not this invocation is
 *          being used to prepare a binary for deployment into a
 *          build cache. If this is true, the import library is not
 *          re-written to create an absolute path, and the dll names
 *          in the dll are not made to be absolute paths, instead
 *          a spack sigil is injected into the names so we can identify
 *          them as Spack paths
 * Full -   this flag informs the process as to whether we're relocating a DLL or
 *          just its import library. If we're doing a "full" pass, we
 *          produce a new import library with the absolute path to its dll
 *          AND we re-write all external DLL references in the DLL itself. If this
 *          is false and we're not doing a "full" build, we only re-write
 *          the import lib
 * 
 * \param pe the PE file for which to perform the rename of imported (and exported) DLL names
 * \param full a flag indicating whether or not we're renaming a PE file and import lib or just an import lib
 * \param deploy a flag indicating if we're deploying a binary to a Spack build cache or extracting it
 * \param replace a flag indicating if we're replacing the renamed import lib or making a copy with absolute dll names
 * \param report a flag indicating if we should be reporting the contents of the PE/COFF file we're parsing to stdout
*/
LibRename::LibRename(std::string pe, bool full, bool deploy, bool replace)
    : replace(replace),
      full(full),
      pe(std::move(std::move(pe))),
      deploy(deploy) {}

LibRename::LibRename(std::string pe, std::string coff, bool full, bool deploy,
                     bool replace)
    : replace(replace),
      full(full),
      pe(std::move(std::move(pe))),
      deploy(deploy),
      coff(std::move(std::move(coff))) {
    this->is_exe = endswith(this->pe, ".exe");
    std::string const coff_path = stem(this->coff);
    this->tmp_def_file = coff_path + "-tmp.def";
    this->def_file = coff_path + ".def";
    this->def_executor =
        ExecuteCommand("dumpbin.exe", {this->ComputeDefLine()});
    this->lib_executor = ExecuteCommand("lib.exe", {this->ComputeRenameLink()});
}

/**
 * Creates the line to be provided to dumpbin.exe to produce the exports of a given
 * dll in the case where we do not have access to the original link line
 * 
 * Produces something like `/EXPORTS <name of coff file>`
 */
std::string LibRename::ComputeDefLine() {
    return "/NOLOGO /EXPORTS " + this->coff;
}

/**
 * Drives the process of running dumpbin.exe on a PE file to determine its exports
 * and produce a `.def` file
 * 
 * Returns the return code of the Def file computation operation
 */
bool LibRename::ComputeDefFile() {
    this->def_executor.Execute(this->tmp_def_file);
    int const res = this->def_executor.Join();
    if (res) {
        return false;
    }
    // Need to process the produced def file because it's wrong
    // Open input file
    std::ifstream input_file(this->tmp_def_file);
    if (!input_file.is_open()) {
        std::cerr << "Error: Could not open input file " << tmp_def_file
                  << '\n';
        return false;
    }

    // Open output file
    std::ofstream output_file(this->def_file);
    if (!output_file.is_open()) {
        std::cerr << "Error: Could not open output file " << this->def_file
                  << '\n';
        return false;
    }

    // Write the standard .def file header
    // You might want to get the DLL name dynamically from the input filename or dumpbin output
    output_file << "EXPORTS\n";

    std::string line;
    // Read until the output column titles
    while (std::getline(input_file, line)) {
        std::string const res = regexSearch(line, R"(ordinal\s+name)");
        if (!res.empty()) {
            break;
        }
    }
    while (std::getline(input_file, line)) {
        if (line.empty()) {
            continue;
        }
        if (line.find("Summary") !=
            std::string::
                npos) {  // Skip header in export block if still present
            break;
        }
        output_file << "    " << regexReplace(line, R"(\s+)", "") << '\n';
    }
    input_file.close();
    output_file.close();
    std::remove(this->tmp_def_file.c_str());
    return true;
}

/**
 * End to end PE + COFF rename process driver
 *  Produces a `.def` file describing the exports of a given PE file
 *  and then generates an import library with absolute paths to the
 *  corresponding dll or generates a dll with absolute paths to its
 *  dependencies depending on the context
 * 
 * Returns 0 on failure, 1 otherwise
 * 
 * On standard deployment, we don't do anything
 * On standard extraction, we want to regenerate the import library
 *  from our import library pointing to the new location of the dll/exe
 *  post buildcache extraction
 * 
 * On a full deployment, we mark the spack based DLL names in the binary
 *  with a spack sigil <sp!>
 * 
 * On a full extraction, in addition to the standard extraction operation
 *  we rename the Dll names marked with the spack sigil (<sp!>)
 *
 */
bool LibRename::ExecuteRename() {
    // If we're not deploying, we're extracting
    // recompute the .def and .lib for dlls
    // exes do not typically have import libs so we don't handle
    // that case
    // We do not bother with defs for things that don't have
    // import libraries
    if (!this->deploy && !this->coff.empty()) {
        // Extract DLL
        if (!this->ComputeDefFile()) {
            debug("Failed to compute def file");
            return false;
        }
        if (!this->ExecuteLibRename()) {
            debug("Failed to create and rename import lib");
            return false;
        }
    }
    if (this->full) {
        if (!this->ExecutePERename()) {
            std::cerr << "Unable to execute rename of "
                         "referenced components in PE file: "
                      << this->pe << "\n";
            return false;
        }
    }
    return true;
}

/**
 * Drives the rename procedure for an import library
 *   Creates a new import library from a def file with
 *   a mangled variation of the absolute path to the dll
 *   as its dll name, and then modifies that binary to correct
 *   and unmangle the mangled dll name
 * 
 */
bool LibRename::ExecuteLibRename() {
    this->lib_executor.Execute();
    int const ret_code = this->lib_executor.Join();
    if (ret_code != 0) {
        std::cerr << "Lib Rename failed with exit code: " << ret_code << "\n";
        return false;
    }
    // replace former .lib with renamed .lib
    std::remove(this->coff.c_str());
    std::rename(this->new_lib.c_str(), this->coff.c_str());
    // import library has been generated with
    // mangled abs path to dll -
    // unmangle it
    CoffReaderWriter cr(this->coff);
    CoffParser coff(&cr);
    int const coff_parse_valid = coff.Verify();
    if (coff_parse_valid) {
        std::cerr << "Unable to parse generated import library {"
                  << this->new_lib << "}: ";
        std::string const err = coff_parse_valid > 1
                                    ? "Error parsing library\n"
                                    : "Library is static, not import\n";
        std::cerr << err;
        return false;
    }
    std::string mangled_name = mangle_name(this->pe);
    if (!coff.NormalizeName(mangled_name)) {
        std::cerr << "Unable to normalize name: " << mangled_name << "\n";
        return false;
    }
    return true;
}

/**
 * Drives the rename process for 
 * 
 */
bool LibRename::ExecutePERename() {
    std::wstring const pe_path = ConvertAnsiToWide(this->pe);
    HANDLE pe_handle = CreateFileW(
        pe_path.c_str(), (GENERIC_READ | GENERIC_WRITE), FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!pe_handle || pe_handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Unable to acquire file handle to " << pe_path.c_str()
                  << ": " << reportLastError() << "\n";
        return false;
    }
    return this->FindDllAndRename(pe_handle);
}

/* Construct the line needed to produce a new import library
 * given a set of symbols exported by a DLL and stored in a module definition (.def) file,
 * the current import lib and a name for said DLL, which in 
 * our case is the mangled DLL absolute path. This creates 
 * an import libray with a mangled absolute path to the DLL 
 * as its DLL name which we then unmangle to produce the "rpath" that
 * will be injected into binaries that link against this.
 * 
 * This method will inject a dll name that is mangled, as in the examples
 * below. A followup step, performed by this wrapper, specifically the CoffParser,
 * is required to actually go into the binary, and un-mangle that name.
 * This is due to constraints placed on the linker and archiver command lines by MS.
 * 
 * A rename line looks something like
 * 
 * -def:foo.def -name:C;|abs|path|to|foo.dll -out:foo.dll-abs.lib foo.lib
 * 
 * If we're replacing the current binary
 * 
 * -def:foo.def -name:C;|abs|path|to|foo.dll -out:foo.lib foo.lib
 * 
*/
std::string LibRename::ComputeRenameLink() {
    std::string line("-def:");
    line += this->def_file + " ";
    line += "-name:";
    line += mangle_name(this->pe) + " ";
    std::string const name(stem(this->coff));
    if (!this->replace) {
        this->new_lib = name + ".abs-name.lib";
    } else {
        // Name must be different
        this->new_lib = name + "-tmp.lib";
    }
    line += "-out:\"" + this->new_lib + "\"";
    return line;
}
