/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once
#include "winrpath.h"
#include "coff_pe_reporter.h"

#include <sstream>

#define BUFSIZE 4096

using CoffMembers = std::vector<coff_entry>;


const std::map<char, char> special_character_to_path{
    {'|', '\\'},
    {';', ':'}
};

const std::map<char, char> path_to_special_characters{
    {'\\', '|'},
    {'/', '|'},
    {':', ';'}
};

/**
 * Replaces characters used to mangle path characters with
 * valid path characters
 * 
 * \param in a pointer to the string to replace the mangled path characters in
 * \param len the length of the mangled path
 */
void replace_special_characters(char in[], int len)
{
    for (int i = 0; i < len; ++i) {
        if (special_character_to_path.count(in[i]))
        {
            in[i] = special_character_to_path.at(in[i]);
        }
            
    }
}

/**
 * Replaces path characters with special, non path, replacement characters
 * 
 * \param in a pointer to the string to have its path characters replace with special placeholders
 * \param len the length of the path to be mangled
 */
void replace_path_characters(char in[], int len)
{
    for (int i = 0; i < len; i++ ) {
        if (path_to_special_characters.count(in[i]))
            in[i] = path_to_special_characters.at(in[i]);
    }
}

/**
 * Pads a given path with an amount of padding of special characters
 * 
 * \param pth a pointer to the path to be padded
 * \param str_size the length of the path
 * \param bsize the lengh of the padding to add
 */
char * pad_path(const char *pth, DWORD str_size, DWORD bsize = MAX_NAME_LEN)
{
    size_t extended_buf = bsize - str_size;
    char * padded_path = new char[bsize+1];
    for(int i = 0, j = 0; i < bsize, j < str_size; i++){
        if(i < 2){
            padded_path[i] = pth[j];
            ++j;
        }
        else if(i < extended_buf){
            padded_path[i] = '|';
        }
        else{
            padded_path[i] = pth[j];
            ++j;
        }
    }
    return padded_path;
}

/**
 * Given a padded library path, return how much the path
 *  has been padded
 * 
 *  \param name the path for which to determine pad count
 */
int get_padding_length(const std::string &name)
{
    int c = 0;
    std::string::const_iterator p = name.cbegin();
    p+=2;
    while(p != name.end() && *p == '/') {
        ++c;
    }
    return c;
}

/**
 * Mangles a string representing a path to have no path characters
 *  instead path characters (i.e. \\, :, etc) are replaced with
 *  special replacement characters
 * 
 * \param name the string to be mangled
 */
std::string mangle_name(const std::string &name)
{
    std::string abs_out;
    std::string mangled_abs_out;
    if(IsPathAbsolute(name)){
        abs_out = name;
    }
    else{
        // relative paths, assume they're relative to the CWD of the linker (as they have to be)
        abs_out = join({GetCWD(), name}, "\\");
    }
    char * chr_abs_out = new char [abs_out.length()];
    strcpy(chr_abs_out, abs_out.c_str());
    replace_path_characters(chr_abs_out, abs_out.length());
    // char * padded_path = pad_path(chr_abs_out, abs_out.length(), MAX_PATH);
    mangled_abs_out = chr_abs_out;
    free(chr_abs_out);
    // free(padded_path);
    return mangled_abs_out;
}

/**
 * Parses the command line of a given linker invocation and stores information
 * about that command line and its associated behavior
 */
LinkerInvocation::LinkerInvocation(const std::string &linkLine)
: line(linkLine), is_exe(true)
{
    StrList tokenized_line = split(this->line, " ");
    this->tokens = tokenized_line;
}

LinkerInvocation::LinkerInvocation(const StrList &linkLine)
{
    this->tokens = linkLine;
    this->line = join(linkLine);
}

/**
 * Parses a linker invocation to extract imformation about the artifacts produced
 * and the obj files used to produce it
 */
void LinkerInvocation::Parse()
{
    for (auto token = this->tokens.begin(); token != this->tokens.end(); ++token) {
        if (endswith(*token, ".lib")) {
            this->libs.push_back(*token);
        }
        else if (*token == "/dll" || *token == "/DLL") {
            this->is_exe = false;
        }
        else if (startswith(*token, "-out") || startswith(*token, "/out")) {
            this->output = split(*token, ":")[1];
        }
        else if (endswith(*token, ".obj")) {
            this->objs.push_back(*token);
        }
    }
    std::string ext = this->is_exe ? ".exe" : ".dll";
    if (this->output.empty()){
        this->output = strip(this->objs.front(), ".obj") + ext;
    }
    this->name = strip(this->output, ext);
}

std::string LinkerInvocation::get_name()
{
    return this->name;
}

std::string LinkerInvocation::get_out()
{
    return this->output;
}

std::string LinkerInvocation::get_mangled_out()
{
    return mangle_name(this->output);
}

bool LinkerInvocation::IsExeLink()
{
    return this->is_exe || endswith(this->output, ".exe");
}

CoffReaderWriter::CoffReaderWriter(std::string file) 
: _file(file) {}

bool CoffReaderWriter::Open()
{
    this->pe_stream.open(this->_file, std::ios::in | std::ios::out | std::ios::binary);
    return this->pe_stream.is_open();
}

bool CoffReaderWriter::Close()
{
    this->pe_stream.close();
    return !this->pe_stream.is_open();
}

void CoffReaderWriter::clear()
{
    this->pe_stream.clear();
}

bool CoffReaderWriter::IsOpen()
{
    return this->pe_stream.is_open();
}

bool CoffReaderWriter::IsClosed()
{
    return !this->pe_stream.is_open();
}

bool CoffReaderWriter::ReadSig(coff &coff_in)
{
    this->pe_stream.read((char *)&coff_in.signature, IMAGE_ARCHIVE_START_SIZE);
    return strcmp(coff_in.signature, IMAGE_ARCHIVE_START);
}

void CoffReaderWriter::ReadHeader(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in)
{
    this->pe_stream.read((char*)coff_in, sizeof(IMAGE_ARCHIVE_MEMBER_HEADER));
}

void CoffReaderWriter::ReadMember(PIMAGE_ARCHIVE_MEMBER_HEADER head, coff_member *coff_in)
{
    int member_size = atoi((char*)head->Size);
    coff_in->data = new char[member_size];
    this->pe_stream.read(coff_in->data, member_size);
    if (member_size % 2 != 0) {
        this->seek(1, std::ios_base::cur);
    }
}

std::string CoffReaderWriter::get_file()
{
    return this->_file;
}

std::streampos CoffReaderWriter::tell()
{
    return this->pe_stream.tellg();
}

void CoffReaderWriter::seek(int bytes, std::ios_base::seekdir way)
{
    this->pe_stream.seekg(bytes, way);
}

int CoffReaderWriter::peek()
{
    return this->pe_stream.peek();
}

bool CoffReaderWriter::end()
{
    return this->pe_stream.eof();
}

void CoffReaderWriter::read(char * out, int size)
{
    this->pe_stream.read(out, size);
}

void CoffReaderWriter::write(char * in, int size)
{
    this->pe_stream.write(in, size);
}


CoffParser::CoffParser(CoffReaderWriter * cr)
: coffStream(cr) {}

/**
 * Parses a COFF file from a file stream from an opened file
 * 
 * Performs validation of the correct type and structure of the file
 * by verifying it has a COFF archive signature and is correctly structured
 * and then reads in the file, member by member, and parses the archive header and
 * member utilizing the appropriate scheme (as determine by the COFF scheme) and stores
 * the parsed information in the coffparser object.
 */
bool CoffParser::Parse()
{
    if(!this->coffStream->Open()) {
        std::cerr << "Unable to open coff file for reading: " << GetLastError() << "\n";
        return false;
    }
    int invalid_valid_sig = this->coffStream->ReadSig(this->coff);
    if(invalid_valid_sig) {
        std::cerr << "Invalid signature for expected COFF archive format file: " << this->coffStream->get_file() << "\n";
        return false;
    }
    CoffMembers members;
    while(!(this->coffStream->peek() == EOF)) {
        PIMAGE_ARCHIVE_MEMBER_HEADER header = new IMAGE_ARCHIVE_MEMBER_HEADER;
        coff_member * member = new coff_member;
        std::streampos offset = this->coffStream->tell();
        this->coffStream->ReadHeader(header);
        this->coffStream->ReadMember(header, member);
        this->ParseData(header, member);
        coff_entry entry;
        entry.header = header;
        entry.member = member;
        entry.offset = offset;
        members.emplace_back(entry);
    }
    // validate end of file
    if(!this->coffStream->end()) {
        std::cerr << "Unexpected end of file encountered. Please ensure input file is not corrupted\n";
        return false;
    }
    this->coff.members = members;
    this->coffStream->clear();
    return true;
}

/**
 * Parses a member section in the form of a short format import section
 *  based on the COFF structure scheme
 *
 *  \param member A pointer to the member data to be parsed 
 */
void CoffParser::ParseShortImport(coff_member *member)
{
    IMPORT_OBJECT_HEADER * im_h = (IMPORT_OBJECT_HEADER *)member->data;
    // validate header
    if(!(im_h->Sig1 == 0x00) || !(im_h->Sig2 == 0xFFFF)) {
        return;
    }
    short_import_member *sm = new short_import_member();
    sm->im_h = im_h;
    sm->short_name = (char* )(im_h+1);
    sm->short_dll = sm->short_name + strlen(sm->short_name)+1;
    member->short_member = sm;
    member->is_short = true;
}


/**
 * Parses a member section in the form of a fully qualified import section
 *  based on the COFF structure scheme
 *
 *  \param member A pointer to the member data to be parsed 
 */
void CoffParser::ParseFullImport(coff_member *member)
{
    // Parse image file header
    PIMAGE_FILE_HEADER file_h = (PIMAGE_FILE_HEADER)member->data;
    // Parse section headers
    IMAGE_SECTION_HEADER** p_sections = new PIMAGE_SECTION_HEADER[file_h->NumberOfSections];
    for(int i = 0; i < file_h->NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER sec_h = (PIMAGE_SECTION_HEADER)(member->data + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_SECTION_HEADER)*i);
        *(p_sections+i) = new IMAGE_SECTION_HEADER;
        *(p_sections+i) = sec_h;
    }
    // Parse section data
    char ** section_data = new char *[file_h->NumberOfSections];
    for(int i=0; i<file_h->NumberOfSections; ++i) {
        int data_loc = (*p_sections+i)->PointerToRawData;
        *(section_data+i) = member->data+data_loc;
    }
    // Parse Coff Symbol table
    PIMAGE_SYMBOL * symbol_table = new PIMAGE_SYMBOL[file_h->NumberOfSymbols];
    DWORD symbol_table_offset = file_h->PointerToSymbolTable;
    for(int i=0; i<file_h->NumberOfSymbols;++i) {
        PIMAGE_SYMBOL im_sym = (PIMAGE_SYMBOL)(member->data+symbol_table_offset+(sizeof(IMAGE_SYMBOL)*i));
        *(symbol_table+i) = new IMAGE_SYMBOL;
        *(symbol_table+i) = im_sym;
        BYTE aux_sym = (*(symbol_table+i))->NumberOfAuxSymbols;
    }
    // Parse string table
    DWORD string_table_offset = symbol_table_offset+sizeof(IMAGE_SYMBOL)*file_h->NumberOfSymbols;
    // first four bytes of string table give size of string table
    DWORD size_of_string_table = *(PDWORD)(member->data+string_table_offset);
    char * string_table;
    if (size_of_string_table > 4) {
        // string table size bytes are included in the total size count for the
        // string table
        string_table = member->data+string_table_offset+sizeof(DWORD);
    }
    // We're done reading a given member's data field
    long_import_member *lm = new long_import_member;
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
void CoffParser::ParseFirstLinkerMember(coff_member *member)
{
    DWORD sym_count = *(PDWORD)member->data;
    // Offsets are offset in member data by the sym count entry
    // which is a 4 byte value (DWORD)
    PDWORD poffsets = (PDWORD)(member->data+sizeof(DWORD));
    // symbol count is big endian in coff files but Windows is little endian
    sym_count = ToLittleEndian(sym_count);
    // string table of symbol names comes after symbol count and 
    // the offsets so its offset is the sym size DWORD and the number
    // of symbols (from the first entry) * the 4 byte member header offsets (DWORD)
    char * pnames = member->data+sizeof(DWORD)+(sizeof(DWORD)*sym_count);
    first_linker_member *fl = new first_linker_member;
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
void CoffParser::ParseSecondLinkerMember(coff_member *member)
{
    // Second linker member member count is little endian already
    DWORD archive_member_count = *(PDWORD)member->data;
    PDWORD poffsets = (PDWORD)(member->data+sizeof(DWORD));
    DWORD sym_count = *((PDWORD)(member->data+(archive_member_count*sizeof(DWORD)+sizeof(DWORD))));
    PWORD pindex = (PWORD)(member->data+(2*sizeof(DWORD))+(archive_member_count*sizeof(DWORD)));
    char * names = (char*)pindex+(sym_count*sizeof(WORD));
    second_linker_member *sl = new second_linker_member;
    sl->members = archive_member_count;
    sl->offsets = poffsets;
    sl->symbols = sym_count;
    sl->indicies = pindex;
    sl->strings = names;
    member->second_link = sl;
}

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
 */
void CoffParser::ParseData(PIMAGE_ARCHIVE_MEMBER_HEADER header, coff_member *member)
{
    IMPORT_OBJECT_HEADER * p_imp_header = (IMPORT_OBJECT_HEADER *)member->data;
    if((p_imp_header->Sig1 == IMAGE_FILE_MACHINE_UNKNOWN) && (p_imp_header->Sig2 == IMPORT_OBJECT_HDR_SIG2)) {
        // SHORT IMPORT LIB FORMAT (NT4,SP3)
        this->ParseShortImport(member);
    }
    else if (!strncmp((char*)header->Name, IMAGE_ARCHIVE_LINKER_MEMBER, 16)) {
        if (!this->coff.read_first_linker) {
            this->ParseFirstLinkerMember(member);
            this->coff.read_first_linker = true;
        }
        else {
            this->ParseSecondLinkerMember(member);
        }
    }
    else if (!strncmp((char*)header->Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16)) {
        // Long names member doesn't provide us anything useful to parse
        // at this stage
        return;
    }
    else {
        this->ParseFullImport(member);
    }
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
bool CoffParser::NormalizeName(std::string &name)
{
    // The dll is found with and without an extenion, depending on the context of the location
    // i.e. in the section data, it can be found with both an extension and extensionless
    //  whereas in the symbol table or linker member strings, it's always found without an extension
    std::string name_no_ext = strip(name, ".dll");

    // Iterate through the parsed COFF members
    for (auto mem: this->coff.members) {
        int i = 0;
        // import member names from spack are of the form "      /n" where n is their place
        // in the longnames member, other members are "/[/]        "
        // This allows us to determine if we're looking at an import member, and where the offset is
        // Non Spack no linker/longname members are of the form "    /name-of-dll"
        while(i < 16 && mem.header->Name[i] != ' ') {
            ++i;
        }
        std::string name_ref = std::string((char*)mem.header->Name, i);
        if (!endswith(name_ref, "/")) {
            // We have an import member
            // Name is longer than 16 bytes, need to lookup name in longname offset
            int longname_offset = std::stoi(name_ref.substr(1, std::string::npos));
            // Reconstruct name from location in longnames member
            int long_name_len = strlen(this->coff.members[2].member->data+longname_offset);
            // Longnames member is always the third member if it exists
            // We know it exists at this point due to the success of the conditional above
            char* long_name = new char[long_name_len];
            strncpy(long_name, this->coff.members[2].member->data+longname_offset, long_name_len);
            // Ensure Dll name is the one we're looking to perform the rename for
            if (!strcmp(name.c_str(), long_name)) {
                // If so, unmangle it
                replace_special_characters(long_name, long_name_len);
                // offset of actual longname member
                int offset = std::streamoff(this->coff.members[2].offset);
                this->coffStream->seek(0);
                // Seek to longname header
                this->coffStream->seek(offset);
                // Seek to offset within longname member for a given import name
                this->coffStream->seek(sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) + longname_offset, std::ios_base::cur);
                this->coffStream->write(long_name, long_name_len);
            }
            delete long_name;
            // Import member name has been renamed
            // Now we rename the other DLL references
            // Import members have two forms, long and short, check for short
            if(mem.member->is_short) {
                // short import members are simple and easily parsed, we have
                // direct access to the name we're looking for from the inital parsing pass
                int name_len = strlen(mem.member->short_member->short_dll);
                char * new_name = new char[name_len];
                // unmangle it
                strcpy(new_name, mem.member->short_member->short_dll);
                replace_special_characters(new_name, name_len);
                // ensure it's the name we're looking to rename
                if(!strcmp(name.c_str(), mem.member->short_member->short_dll)) {
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
                    this->coffStream->seek(0);
                    this->coffStream->seek(offset);
                    this->coffStream->write(new_name, strlen(new_name));
                }
                delete new_name;
            }
            else {
                // Rename standard import members
                // First perform the section data renames
                WORD section_data_count = mem.member->long_member->pfile_h->NumberOfSections;
                for(int j=0; j<section_data_count; ++j) {
                    PIMAGE_SECTION_HEADER psec_header =  *(mem.member->long_member->pp_sections+j);
                    // Get section data size from corresponding section header
                    int data_size = psec_header->SizeOfRawData;
                    int virtual_size = psec_header->Misc.VirtualSize;
                    // Determine section data padding size
                    if (virtual_size > data_size) {
                        data_size += (virtual_size - data_size);
                    }
                    // section start offset in file
                    DWORD section_data_start_offset = std::streamoff(mem.offset) + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) + psec_header->PointerToRawData;
                    // section start is longmember section pointer + index
                    char * section = *(mem.member->long_member->section_data+j);
                    char * section_search_start = &*section;
                    char * search_terminator = section+data_size;
                    // search section data for full name
                    int name_len = name.size();
                    while(section_search_start && (section_search_start < search_terminator)) {
                        section_search_start = findstr(section_search_start, name.c_str(), data_size);
                        if (section_search_start) {
                            // we found a name, rename
                            ptrdiff_t section_data_offset = section_search_start - section;
                            char * new_name = new char[name_len];
                            strncpy(new_name, section_search_start, name_len);
                            replace_special_characters(new_name, name_len);
                            this->coffStream->seek(0);
                            this->coffStream->seek(section_data_start_offset + section_data_offset);
                            this->coffStream->write(new_name, name_len);
                            delete new_name;   
                            section_search_start += name_len+1;                   
                        }
                    }
                    // search section data for extensionless name
                    name_len = name_no_ext.size();
                    section_search_start = &*section;
                    while(section_search_start && (section_search_start < search_terminator)) {
                        section_search_start = findstr(section_search_start, name_no_ext.c_str(), name_len);
                        if (section_search_start) {
                            // we found a name, rename
                            ptrdiff_t offset = section_search_start - section;
                            char * new_name = new char[name_len];
                            strncpy(new_name, section_search_start, name_len);
                            replace_special_characters(new_name, name_len);
                            this->coffStream->seek(0);
                            this->coffStream->seek(section_data_start_offset + offset);
                            this->coffStream->write(new_name, name_len);    
                            delete new_name;
                            section_search_start += name_len+1;                
                        }
                    }
                }
                // Section data rename is complete, now rename string table
                int relative_string_table_start_offset = std::streamoff(mem.offset) + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) + mem.member->long_member->string_table_offset + sizeof(DWORD);
                char * string_table_start, *string_table = mem.member->long_member->string_table;
                int symbol_count = mem.member->long_member->pfile_h->NumberOfSymbols;
                PIMAGE_SYMBOL * symbols = mem.member->long_member->symbol_table;
                for(int j=0;j<symbol_count;++j) {
                    PIMAGE_SYMBOL symbol = *(symbols+j);
                    if(symbol->N.Name.Short == 0) {
                        // name is longer than 8 bytes, it's a Spack name, search
                        DWORD name_string_table_offset = symbol->N.Name.Long-sizeof(DWORD);
                        string_table_start = strstr((string_table+name_string_table_offset), name_no_ext.c_str());
                        if (string_table_start && (string_table_start < string_table+mem.member->long_member->size_of_string_table)) {
                            ptrdiff_t offset = string_table_start - string_table;
                            int name_len = name_no_ext.size();
                            char * new_no_ext_name = new char[name_len];
                            strncpy(new_no_ext_name, string_table_start, name_len);
                            replace_special_characters(new_no_ext_name, name_len);
                            this->coffStream->seek(0);
                            this->coffStream->seek(relative_string_table_start_offset + offset);
                            this->coffStream->write(new_no_ext_name, name_len);
                            delete new_no_ext_name;
                        }
                    }
                }

            }
        }
        else if (!strncmp((char*)mem.header->Name, IMAGE_ARCHIVE_LINKER_MEMBER, 16)) {
            // This is the first linker member, utilize the structure of the member to locate the
            // symbols section and search the symbols for our mangled dll name.
            // if found, replace with the unmangled version
            int base_offset = std::streamoff(mem.offset);
            int offset_with_header = base_offset + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
            int current_relative_offset = 0;
            if (mem.member->first_link) {
                int member_offset = sizeof(DWORD) + mem.member->first_link->symbols*sizeof(DWORD);
                for (int j=0; j < mem.member->first_link->symbols; ++j) {
                    int name_len = strlen(mem.member->first_link->strings+current_relative_offset);
                    char * new_name = new char[name_len];
                    strcpy(new_name, mem.member->first_link->strings+current_relative_offset);
                    if(strstr(new_name, name_no_ext.c_str())) {
                        replace_special_characters(new_name, name_len);
                        int offset = offset_with_header + member_offset + current_relative_offset;
                        this->coffStream->seek(0);
                        this->coffStream->seek(offset);
                        this->coffStream->write(new_name, name_len);
                    }
                    current_relative_offset += name_len+1;
                }
            }
            else {
                // rename second linker member names
                int member_offset = sizeof(DWORD) + sizeof(DWORD) * mem.member->second_link->members + sizeof(DWORD) + sizeof(WORD) * mem.member->second_link->symbols;
                for(int j=0; j<mem.member->second_link->symbols;++j) {
                    int name_len = strlen(mem.member->second_link->strings+current_relative_offset);
                    char * new_name = new char[name_len];
                    strcpy(new_name, mem.member->second_link->strings+current_relative_offset);
                    if(strstr(new_name, name_no_ext.c_str())) {
                        replace_special_characters(new_name, name_len);
                        int offset = offset_with_header + member_offset + current_relative_offset;
                        this->coffStream->seek(0);
                        this->coffStream->seek(offset);
                        this->coffStream->write(new_name, name_len);                        
                    }
                    current_relative_offset += name_len+1;
                }
            }
        }
        else if (!strncmp((char*)mem.header->Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16)){
            // This is the longnames member, if we wanted to rename it directly we'd have to search through the
            // entire thing, wereas if we iterate to the import members, their names will give us the offset of
            // their name in the longnames member, meaning this can be a constant time operation if performed from
            // another context
            continue;
        }
        else {
            // If it's not an archive member or a long names offset based name, its either something we don't recognize
            // or it's a non Spack derived import
            // TODO: Optionally warn rather than always report to std error, for externals this
            // will create way too much noise
            std::cerr << "Unrecognized or non Spack based import member: " << mem.header->Name << "\n";
        }        
    }
    this->coffStream->Close();
    return true;
}


void CoffParser::ReportLongImportMember(long_import_member *li)
{
    reportFileHeader(li->pfile_h);
    reportCoffSections(li);
    reportCoffSymbols(li);    
}


void CoffParser::ReportShortImportMember(short_import_member *si)
{
    reportImportObjectHeader(si->im_h);
    std::cout << "  DLL: " <<si->short_dll << "\n";
    std::cout << "  Name: " << si->short_name << "\n";
}


void CoffParser::Report()
{
    for (auto mem: this->coff.members) {
        reportArchiveHeader(mem.header);
        if(mem.member->long_member) {
            this->ReportLongImportMember(mem.member->long_member);
        }
        else if(mem.member->short_member) {
            this->ReportShortImportMember(mem.member->short_member);
        }
    }
}


int reportCoff(CoffParser &coff)
{
    if(!coff.Parse()){
        return 1;
    }
    coff.Report();
    return 0;
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
bool LibRename::SpackCheckForDll(const std::string &name)
{
    if(this->deploy){
        for(std::map<char, char>::const_iterator it = path_to_special_characters.begin(); it != path_to_special_characters.end(); ++it){
            if(!(name.find(it->first) == std::string::npos)){
                return true;
            }
        }
        return false;
    }
    else {
        return (!(name.find("<!spack>") == std::string::npos));
    }
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
*/
int LibRename::RenameDll(char* name_loc, const std::string &dll_name)
{
    if(this->deploy) {
        int padding_len = get_padding_length(dll_name);
        if(padding_len < 8) {
            // path is too long to mark as a Spack path
            // use shorter sigil
            char short_sigil[] = "<sp>";
            snprintf(name_loc, sizeof(short_sigil), "%s", short_sigil); 
        }
        else {
            char long_sigil[] = "<!spack>";
            snprintf(name_loc, sizeof(long_sigil), "%s", long_sigil);
        }
    }
    else {
        std::string file_name = basename(dll_name);
        if(file_name.empty()) {
            std::cerr << "Unable to extract filename from dll for relocation" << "\n";
            return -1;
        }
        LibraryFinder lf;
        std::string new_library_loc = lf.FindLibrary(file_name);
        if(new_library_loc.empty()) {
            std::cerr << "Unable to find library for relocation" << "\n";
            return -1;
        }
        snprintf(name_loc, new_library_loc.size(), "%s", new_library_loc.c_str());
    }
    return 1;
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
*/
int LibRename::FindDllAndRename(HANDLE &pe_in)
{
    HANDLE hMapObject = CreateFileMapping(pe_in, NULL, PAGE_READWRITE, 0, 0, NULL);
    if(!hMapObject){
        std::cerr << "Unable to create mapping object\n";
        return -5;
    }
    LPVOID basepointer = (char*)MapViewOfFile(hMapObject, FILE_MAP_WRITE, 0, 0, 0);
    if(!basepointer){
        std::cerr << "Unable to create file map view\n";
        return -6;
    }
    // Establish base PE headers
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)basepointer;
    PIMAGE_NT_HEADERS nt_header = 
        (PIMAGE_NT_HEADERS)((char*)basepointer + dos_header->e_lfanew);

    PIMAGE_FILE_HEADER coff_header = 
        (PIMAGE_FILE_HEADER)((char*)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature));
        
    PIMAGE_OPTIONAL_HEADER optional_header = 
        (PIMAGE_OPTIONAL_HEADER)((char*)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader));
        
    PIMAGE_SECTION_HEADER section_header = 
        (PIMAGE_SECTION_HEADER)((char*)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + sizeof(nt_header->OptionalHeader));
    
    DWORD number_of_rva_and_sections = optional_header->NumberOfRvaAndSizes;
    if(number_of_rva_and_sections == 0) {
        std::cerr << "PE file does not import symbols" << "\n";
        return -1;
    }
    else if(number_of_rva_and_sections < 2) {
        std::cerr << "PE file contains insufficient data directories, likely corrupted" << "\n";
        return -2;
    }

    DWORD number_of_sections = coff_header->NumberOfSections;
    // Data directory #2 points to the RVA of the import section
    DWORD RVA_import_directory = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD import_section_file_offset = RvaToFileOffset(section_header, number_of_sections, RVA_import_directory);
    char * import_table_offset = (char*)basepointer + import_section_file_offset;
    PIMAGE_IMPORT_DESCRIPTOR import_image_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(import_table_offset);
    //DLL Imports
    for (; import_image_descriptor->Name != 0; import_image_descriptor++) {
        char* Imported_DLL = import_table_offset + (import_image_descriptor->Name - RVA_import_directory);
        std::ostringstream str_stream;
        str_stream << Imported_DLL;
        if(this->SpackCheckForDll(str_stream.str())) {
            if(!this->RenameDll(Imported_DLL, str_stream.str())) {
                std::cerr << "Unable to relocate DLL\n";
                return 0;
            }
        }
    }
    if(!SafeHandleCleanup(basepointer) || !SafeHandleCleanup(hMapObject)) {
        return -3;
    }
    return 1;
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
*/
LibRename::LibRename(std::string pe, bool full, bool deploy, bool replace, bool report)
: replace(replace), full(full), pe(pe), deploy(deploy)
{
    this->name = stem(this->pe);
    this->is_exe = endswith(this->pe, ".exe");
    this->def_file = this->name + ".def";
    this->def_executor = ExecuteCommand("dumpbin.exe", {this->ComputeDefLine()});
    this->lib_executor = ExecuteCommand("lib.exe", {this->ComputeRenameLink()});
}

/**
 * Creates the line to be provided to dumpbin.exe to produce the exports of a given
 * dll in the case where we do not have access to the original link line
 * 
 * Produces something like `/EXPORTS <name of pe file`
 */
std::string LibRename::ComputeDefLine()
{
    return "/EXPORTS " + this->pe;
}

/**
 * Drives the process of running dumpbin.exe on a PE file to determine its exports
 * and produce a `.def` file
 */
int LibRename::ComputeDefFile()
{
    return this->def_executor.Execute(this->def_file);
}

/**
 * End to end PE + COFF rename process driver
 *  Produces a `.def` file describing the exports of a given PE file
 *  and then generates an import library with absolute paths to the
 *  corresponding dll or generates a dll with absolute paths to its
 *  dependencies depending on the context
 * On standard deployment, we don't do anything
 * On standard extraction, we want to regenerate the import library
 *  from out dll or exe pointing to the new location of the dll/exe
 *  post buildcache extraction
 * 
 * On a full deployment, we mark the spack based DLL names in the binary
 *  with a spack sigil <sp!>
 * 
 * On a full extraction, in addition to the standard extraction operation
 *  we rename the Dll names marked with the spack sigil (<sp!>)
 *
 */
int LibRename::ExecuteRename()
{
    if(!this->deploy){
        if(!this->ComputeDefFile()) {
            return 0;
        }
        if(!this->ExecuteLibRename()) {
            return 0;
        }
    }
    if (this->full) {
        if(!this->ExecutePERename()) {
            std::cerr << "Unable to execute rename of "
                "referenced components in PE file: " << this->name << "\n";
            return 0;
        }
    }
    return 1;
}

/**
 * Drives the rename procedure for an import library
 *   Creates a new import library from a def file with
 *   a mangled variation of the absolute path to the dll
 *   as its dll name, and then modifies that binary to correct
 *   and unmangle the mangled dll name
 */
int LibRename::ExecuteLibRename()
{
    this->lib_executor.Execute();
    int ret_code = this->lib_executor.Join();
    if(!ret_code) {
        std::cerr << GetLastError();
        return ret_code;
    }
    // import library has been generated with
    // mangled abs path to dll -
    // unmangle it
    CoffReaderWriter cr(this->new_lib);
    CoffParser coff(&cr);
    if (!coff.Parse()) {
        std::cerr << "Unable to parse generated import library {" << this->new_lib <<"}\n";
        return 0;
    }
    if(!coff.NormalizeName(mangle_name(this->pe) )) {
        std::cerr << "Unable to normalize name\n";
        return 0;
    }
    return 1;
}

/**
 * Drives the rename process for 
 */
int LibRename::ExecutePERename()
{
    LPCWSTR lib_name = ConvertAnsiToWide(this->pe).c_str();
    HANDLE pe_handle = CreateFileW(lib_name, (GENERIC_READ|GENERIC_WRITE), FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!pe_handle){
        std::stringstream os_error;
        os_error << GetLastError();
        std::cerr << "Unable to acquire file handle: " << os_error.str() << "\n";
        return 0;
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
std::string LibRename::ComputeRenameLink()
{
    std::string line("-def:");
    line += this->def_file + " ";
    line += "-name:";
    line += mangle_name(this->pe) + " ";
    std::string name(stem(this->pe));
    if (!this->replace){
        this->new_lib = name + ".abs-name.lib";
    }
    else {
        this->new_lib = this->pe;
    }
    line += "-out:\""+ this->new_lib + "\"" + " " + this->pe;
    return line;
}
