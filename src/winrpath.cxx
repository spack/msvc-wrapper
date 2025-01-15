#pragma once
#include "winrpath.h"
#include "utils.h"

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
 * 
 */
void replace_special_characters(char in[], int len)
{
    for (int i = 0; i < len; ++i) {
        if (special_character_to_path.count(in[i]))
            in[i] = special_character_to_path.at(in[i]);
    }
}

/**
 * 
 */
void replace_path_characters(char in[], int len)
{
    for (int i = 0; i < len; i++ ) {
        if (path_to_special_characters.count(in[i]))
            in[i] = path_to_special_characters.at(in[i]);
    }
}

/**
 * 
 */
char * pad_path(const char *pth, DWORD str_size, DWORD bsize = MAX_PATH)
{
    size_t extended_buf = bsize - str_size;
    char * padded_path = new char[bsize+1];
    for(int i = 0, j = 0; i < bsize, j < str_size; i++){
        if(i < 2){
            padded_path[i] = pth[j];
            ++j;
        }
        else if(i < extended_buf){
            padded_path[i] = '/';
        }
        else{
            padded_path[i] = pth[j];
            ++j;
        }
    }
}

/**
 * 
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
 * 
 */
std::string mangle_name(const std::string &name)
{
    std::string abs_out;
    std::string mangled_abs_out;
    if(isPathAbsolute(name)){
        abs_out = name;
    }
    else{
        // relative paths, assume they're relative to the CWD of the linker (as they have to be)
        abs_out = join({getCWD(), name}, "\\");
    }
    char * chr_abs_out = new char [abs_out.length()];
    strcpy(chr_abs_out, abs_out.c_str());
    replace_path_characters(chr_abs_out, abs_out.length());
    char * padded_path = pad_path(chr_abs_out, abs_out.length(), MAX_PATH);
    mangled_abs_out = padded_path;
    free(chr_abs_out);
    free(padded_path);
    return mangled_abs_out;
}

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
 * 
 */
void LinkerInvocation::parse()
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

bool LinkerInvocation::is_exe_link()
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

bool CoffReaderWriter::isOpen()
{
    return this->pe_stream.is_open();
}

bool CoffReaderWriter::isClosed()
{
    return !this->pe_stream.is_open();
}

bool CoffReaderWriter::read_sig(coff &coff_in)
{
    this->pe_stream.read((char *)&coff_in.signature, IMAGE_ARCHIVE_START_SIZE);
    return strcmp(coff_in.signature, IMAGE_ARCHIVE_START);
}

void CoffReaderWriter::read_header(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in)
{
    this->pe_stream.read((char*)&coff_in, sizeof(PIMAGE_ARCHIVE_MEMBER_HEADER));
}

void CoffReaderWriter::read_member(PIMAGE_ARCHIVE_MEMBER_HEADER head, coff_member& coff_in)
{
    int member_size;
    memcpy(&member_size, head->Size, sizeof(int));
    coff_in.data = new char[member_size];
    this->pe_stream.read(coff_in.data, member_size);
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
 * 
 */
bool CoffParser::parse()
{
    if(!this->coffStream->Open()) {
        std::cerr << "Unable to open coff file for reading: " << (char*)GetLastError() << "\n";
        return false;
    }
    if(!this->coffStream->read_sig(this->coff_)) {
        std::cerr << "Invalid signature for expected COFF archive format file: " << this->coffStream->get_file() << "\n";
        return false;
    }
    CoffMembers members;
    while(!this->coffStream->end()) {
        PIMAGE_ARCHIVE_MEMBER_HEADER header;
        coff_member member;
        std::streampos offset = this->coffStream->tell();
        this->coffStream->read_header(header);
        this->coffStream->read_member(header, member);
        this->parse_data(header, member);
        coff_entry entry;
        entry.header = header;
        entry.member = member;
        entry.offset = offset;
        members.emplace_back(entry);
    }
    this->coff_.members = members;
    this->coffStream->clear();
    return true;
}

/**
 * 
 */
void CoffParser::parse_short_import(coff_member &member)
{
    IMPORT_OBJECT_HEADER * im_h = (IMPORT_OBJECT_HEADER *)member.data;
    // validate header
    if(!(im_h->Sig2 == 0x00) || !(im_h->Sig2 == 0xFFFF)) {
        return;
    }
    short_import_member *sm = new short_import_member();
    sm->im_h = im_h;
    sm->short_name = (char* )(im_h+1);
    sm->short_dll = sm->short_name + strlen(sm->short_name)+1;
    member.short_member = sm;
}


/**
 * 
 */
void CoffParser::parse_full_import(coff_member &member)
{
    // Parse image file header
    PIMAGE_FILE_HEADER file_h = (PIMAGE_FILE_HEADER)member.data;
    // Parse section headers
    IMAGE_SECTION_HEADER** p_sections = new PIMAGE_SECTION_HEADER[file_h->NumberOfSections];
    for(int i = 0; i < file_h->NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER sec_h = (PIMAGE_SECTION_HEADER)(member.data + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_SECTION_HEADER)*i);
        *(p_sections+i) = new IMAGE_SECTION_HEADER;
        *(p_sections+i) = sec_h;
    }
    // Parse section data
    char ** section_data = new char *[file_h->NumberOfSections];
    for(int i=0; i<file_h->NumberOfSections; ++i) {
        int data_size = (*p_sections+i)->SizeOfRawData;
        int data_loc = (*p_sections+i)->PointerToRawData;
        int virtual_size = (*p_sections+i)->Misc.VirtualSize;
        // Determine section data padding size
        if (virtual_size > data_size) {
            data_size += (virtual_size - data_size);
        }
        *(section_data+i) = new char[data_size];
        this->coffStream->seek(0);
        this->coffStream->seek(data_loc);
        this->coffStream->read(*(section_data+i), data_size);
    }
    // Parse Coff Symbol table
    this->coffStream->seek(0);
    this->coffStream->seek(file_h->PointerToSymbolTable);
    IMAGE_SYMBOL ** symbol_table = new IMAGE_SYMBOL*[file_h->NumberOfSymbols];
    for(int i=0; i<file_h->NumberOfSymbols;++i) {
        *(symbol_table+i) = new IMAGE_SYMBOL;
        this->coffStream->read((char*)*(symbol_table+i), sizeof(IMAGE_SYMBOL));
        BYTE aux_sym = (*(symbol_table+i))->NumberOfAuxSymbols;
    }
    // Parse string table
    DWORD size_of_string_table;
    long long string_table_offset = std::streamoff(this->coffStream->tell());
    // first four bytes of string table give size of string table
    this->coffStream->read((char*)(&size_of_string_table), sizeof(DWORD));
    char * string_table;
    if (size_of_string_table > 4) {
        // string table size bytes are included in the total size count for the
        // string table, read symbols into symbol string table.
        string_table = new char[size_of_string_table-4];
        this->coffStream->read(string_table, size_of_string_table-4);
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
    member.long_member = lm;
}

/**
 * 
 */
void CoffParser::parse_first_linker_member(coff_member &member)
{
    DWORD sym_count = *(PDWORD)member.data;
    PDWORD poffsets = (PDWORD)member.data+4;
    sym_count = to_little_endian(sym_count);
    char * pnames = member.data+(4*sym_count);
    first_linker_member *fl = new first_linker_member;
    fl->offsets = poffsets;
    fl->symbols = sym_count;
    fl->strings = pnames;
    member.first_link = fl;
}

void CoffParser::parse_second_linker_member(coff_member &member)
{
    DWORD archive_member_count = *(PDWORD)member.data;
    archive_member_count = to_little_endian(archive_member_count);
    PDWORD poffsets = (PDWORD)member.data+4;
    DWORD sym_count = *((PDWORD)member.data+archive_member_count*sizeof(DWORD)+4);
    PWORD pindex = (PWORD)member.data+8+archive_member_count*sizeof(DWORD);
    char * names = (char*)pindex+sym_count*sizeof(WORD);
    second_linker_member *sl = new second_linker_member;
    sl->members = archive_member_count;
    sl->offsets = poffsets;
    sl->symbols = sym_count;
    sl->indicies = pindex;
    sl->strings = names;
    member.second_link = sl;
}

/**
 * 
 */
void CoffParser::parse_data(PIMAGE_ARCHIVE_MEMBER_HEADER header, coff_member &member)
{
    IMPORT_OBJECT_HEADER * p_imp_header = (IMPORT_OBJECT_HEADER *)member.data;
    if((p_imp_header->Sig1 == IMAGE_FILE_MACHINE_UNKNOWN) && (p_imp_header->Sig2 == IMPORT_OBJECT_HDR_SIG2)) {
        // SHORT IMPORT LIB FORMAT (NT4,SP3)
        this->parse_short_import(member);
    }
    else if (!strncmp((char*)header->Name, IMAGE_ARCHIVE_LINKER_MEMBER, 16)) {
        if (!this->coff_.read_first_linker) {
            this->parse_first_linker_member(member);
            this->coff_.read_first_linker = true;
        }
        else {
            this->parse_second_linker_member(member);
        }
    }
    else if (!strncmp((char*)header->Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16)) {
        // Long names member doesn't provide us anything useful to parse
        // at this stage
        return;
    }
    else {
        this->parse_full_import(member);
    }
}

/**
 * Takes a zero indexed section number and a coff member
 * and computes the offset to the start of section data corresponding to
 * the given section number within the section data field of a long
 * import member
 */
int CoffParser::compute_section_data_offset(int section_number, long_import_member *mem)
{
    return (*(mem->pp_sections+section_number))->PointerToRawData;
}


/**
 * 
 */
bool CoffParser::normalize_name(std::string &name)
{
    std::string name_no_ext = strip(name, ".dll");
    for (auto mem: this->coff_.members) {
        int i = 0;
        while(i < 16 && mem.header->Name[i] != ' ') {
            ++i;
        }
        std::string name_ref = std::string((char*)mem.header->Name, i);
        if (!endswith(name_ref, "/")) {
            
            // Name is longer than 16 bytes, need to lookup name in longname offset
            int longname_offset = std::stoi(name_ref.substr(1, std::string::npos));
            // Longnames member is always the third member if it exists
            // We know it exists at this point due to the success of the conditional above
            std::vector<char> new_name;
            // Reconstruct name from location in longnames member
            int i;
            for (i = longname_offset; this->coff_.members[2].member.data[i] != '\0'; ++i)
                new_name.push_back(this->coff_.members[2].member.data[i]);
            if (!strcmp(name.c_str(), std::string(new_name.begin(), new_name.end()).c_str())) {
                replace_special_characters((char *)&new_name[0], i-longname_offset);
                int offset = std::streamoff(this->coff_.members[2].offset);
                this->coffStream->seek(offset);
                this->coffStream->seek(sizeof(mem.header) + longname_offset, std::ios_base::cur);
                this->coffStream->write(new_name.data(), new_name.size());
            }
        }
        else if (name_ref == IMAGE_ARCHIVE_LINKER_MEMBER) {
            int base_offset = std::streamoff(mem.offset);
            int offset_with_header = base_offset + sizeof(mem.header);
            int current_relative_offset = 0;
            if (mem.member.first_link) {
                int member_offset = 4 + mem.member.first_link->symbols*sizeof(DWORD);
                for (int i=0; i < mem.member.first_link->symbols; ++i) {
                    int name_len = strlen(mem.member.first_link->strings+current_relative_offset);
                    char * new_name = new char[name_len];
                    strcpy(new_name, mem.member.first_link->strings+current_relative_offset);
                    if(!strcmp(new_name, name.c_str())) {
                        replace_special_characters(new_name, name_len);
                        int offset = offset_with_header + member_offset + current_relative_offset;
                        this->coffStream->seek(0);
                        this->coffStream->seek(offset);
                        this->coffStream->write(new_name, name_len);
                    }
                    current_relative_offset += name_len;
                }
            }
            else {
                // rename second linker member names
                int member_offset = sizeof(DWORD) + sizeof(DWORD) * mem.member.second_link->members + sizeof(DWORD) + sizeof(WORD) * mem.member.second_link->symbols;
                for(int i=0; i<mem.member.second_link->symbols;++i) {
                    int name_len = strlen(mem.member.second_link->strings+current_relative_offset);
                    char * new_name = new char[name_len];
                    strcpy(new_name, mem.member.second_link->strings+current_relative_offset);
                    if(!strcmp(new_name, name.c_str())) {
                        replace_special_characters(new_name, name_len);
                        int offset = offset_with_header + member_offset + current_relative_offset;
                        this->coffStream->seek(0);
                        this->coffStream->seek(offset);
                        this->coffStream->write(new_name, name_len);                        
                    }
                    current_relative_offset += name_len;
                }
            }
        }
        else {
            // Supporting relocation requires a padded path, a path short enough
            // to be in the member header indicates a name incompatible
            // with relocation
            std::cout << "Name too short for relocation, cannot complete relocation operation for member " << mem.header->Name << "\n";
            return false;
        }
        // Name has been renamed
        // Now we rename the other DLL references
        if(mem.member.is_short) {
            int name_len = strlen(mem.member.short_member->short_dll);
            char * new_name = new char[name_len];
            strcpy(new_name, mem.member.short_member->short_dll);
            replace_special_characters(new_name, name_len);
            if(strcmp(name.c_str(), new_name)) {
                // Member offset in file
                int offset = std::streamoff(mem.offset);
                // Member header offset
                offset += sizeof(mem.header);
                // Now need relative offset to dll name in member
                // First entry in short import member is the import header
                offset += sizeof(IMPORT_OBJECT_HEADER);
                // Next is the symbol name, which is a null terminated string
                offset += strlen(mem.member.short_member->short_name);
                this->coffStream->seek(0);
                this->coffStream->seek(offset);
                this->coffStream->write(new_name, strlen(new_name));
            }
            delete new_name;
        }
        else {
            // Rename standard import members
            // First perform the section data renames
            WORD section_data_count = mem.member.long_member->pfile_h->NumberOfSections;
            for(int i=0;i<section_data_count; ++i) {
                int section_data_start_offset = this->compute_section_data_offset(i, mem.member.long_member);
                char * section = *(mem.member.long_member->section_data+i);
                char * section_search_start = *(mem.member.long_member->section_data+i);
                // search section data for full name
                while(section_search_start) {
                    section_search_start = strstr(section_search_start, name.c_str());
                    if (section_search_start) {
                        // we found a name, rename
                        ptrdiff_t offset = section_search_start - section;
                        int name_len = name.size();
                        char * new_name = new char[name_len];
                        strncpy(section_search_start, new_name, name_len);
                        replace_special_characters(new_name, name_len);
                        this->coffStream->seek(0);
                        this->coffStream->seek(section_data_start_offset + offset);
                        this->coffStream->write(new_name, name_len);
                        delete new_name;                      
                    }
                }
                // search section data for extensionless name
                section_search_start = *(mem.member.long_member->section_data+i);
                while(section_search_start) {
                    section_search_start = strstr(section_search_start, name_no_ext.c_str());
                    if (section_search_start) {
                        // we found a name, rename
                        ptrdiff_t offset = section_search_start - section;
                        int name_len = name_no_ext.size();
                        char * new_name = new char[name_len];
                        strncpy(section_search_start, new_name, name_len);
                        replace_special_characters(new_name, name_len);
                        this->coffStream->seek(0);
                        this->coffStream->seek(section_data_start_offset + offset);
                        this->coffStream->write(new_name, name_len);    
                        delete new_name;                    
                    }
                }
            }
            // Section data rename is complete, now rename string table
            int string_table_start_offset = mem.member.long_member->string_table_offset;
            char * string_table_start, *string_table = mem.member.long_member->string_table;
            int symbol_count = mem.member.long_member->pfile_h->NumberOfSymbols;
            PIMAGE_SYMBOL * symbols = mem.member.long_member->symbol_table;
            for(int i=0;i<symbol_count;++i) {
                PIMAGE_SYMBOL symbol = *(symbols+i);
                if(symbol->N.Name.Short == 0) {
                    // name is longer than 8 bytes, it's likely a Spack name, search
                    DWORD name_string_table_offset = symbol->N.Name.Long;
                    // find and rename full name
                    string_table_start = strstr((string_table+name_string_table_offset), name.c_str());
                    if (string_table_start) {
                        ptrdiff_t offset = string_table_start - string_table;
                        int name_len = name.size();
                        char * new_name = new char[name_len];
                        strncpy(string_table_start, new_name, name_len);\
                        replace_special_characters(new_name, name_len);
                        this->coffStream->seek(0);
                        this->coffStream->seek(string_table_start_offset + offset);
                        this->coffStream->write(new_name, name_len);
                        delete new_name;
                    }
                    // find and rename extensionless name
                    string_table_start = strstr((string_table+name_string_table_offset), name_no_ext.c_str());
                    if (string_table_start) {
                        ptrdiff_t offset = string_table_start - string_table;
                        int name_len = name_no_ext.size();
                        char * new_name = new char[name_len];
                        strncpy(string_table_start, new_name, name_len);\
                        replace_special_characters(new_name, name_len);
                        this->coffStream->seek(0);
                        this->coffStream->seek(string_table_start_offset + offset);
                        this->coffStream->write(new_name, name_len);
                        delete new_name;
                    }
                }
            }

        }
    }
    this->coffStream->Close();
    return true;
}

/*
 * Checks a DLL name for special characters, if we're deploying, a path character, if we're
 * relocating a spack sigil
*/
bool LibRename::spack_check_for_dll(const std::string &name)
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
*/
int LibRename::rename_dll(DWORD name_loc, const std::string &dll_name)
{
    if(this->deploy) {
        int padding_len = get_padding_length(dll_name);
        if(padding_len < 8) {
            // path is too long to mark as a Spack path
            // use shorter sigil
            char short_sigil[] = "<sp>";
            snprintf((char*)name_loc, sizeof(short_sigil), short_sigil); 
        }
        else {
            char long_sigil[] = "<!spack>";
            snprintf((char*)name_loc, sizeof(long_sigil), long_sigil);
        }
    }
    else {
        std::string file_name = basename(dll_name);
        if(file_name.empty()) {
            std::cerr << "Unable to extract filename from dll for relocation" << "\n";
            return -1;
        }
        LibraryFinder lf;
        std::string new_library_loc = lf.find_library(file_name);
        if(new_library_loc.empty()) {
            std::cerr << "Unable to find library for relocation" << "\n";
            return -1;
        }
        std::string mangled_padded_new_name = mangle_name(new_library_loc);
        *((LPDWORD) name_loc) = (DWORD)mangled_padded_new_name.c_str();
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
*/
int LibRename::find_dll_and_rename(HANDLE &pe_in)
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
        (PIMAGE_NT_HEADERS)((DWORD)basepointer + dos_header->e_lfanew);

    PIMAGE_FILE_HEADER coff_header = 
        (PIMAGE_FILE_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature));
        
    PIMAGE_OPTIONAL_HEADER optional_header = 
        (PIMAGE_OPTIONAL_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader));
        
    PIMAGE_SECTION_HEADER section_header = 
        (PIMAGE_SECTION_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + sizeof(nt_header->OptionalHeader));
    
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
    DWORD import_table_offset = (DWORD)basepointer + import_section_file_offset;
    PIMAGE_IMPORT_DESCRIPTOR import_image_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(import_table_offset);
    //DLL Imports
    for (; import_image_descriptor->Name != 0; import_image_descriptor++) {
        DWORD Imported_DLL = import_table_offset + (import_image_descriptor->Name - RVA_import_directory);
        std::ostringstream str_stream;
        str_stream << Imported_DLL;
        if(this->spack_check_for_dll(str_stream.str())) {
            if(!this->rename_dll(Imported_DLL, str_stream.str())) {
                std::cerr << "Unable to relocate DLL\n";
                return 0;
            }
        }
    }
    if(!safeHandleCleanup(basepointer) || !safeHandleCleanup(hMapObject)) {
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
 * Full -   this flag informs the process if we're relocating a DLL or
 *          just its import library. If we're doing a "full" pass, we
 *          produce a new import library with the full path to its dll
 *          AND we re-write all DLL references in the DLL itself. If this
 *          is false and we're not doing a "full" build, we only re-write
 *          and import lib
*/
LibRename::LibRename(std::string pe, bool full, bool deploy, bool replace)
: replace(replace), full(full), pe(pe), deploy(deploy)
{
    this->name = stem(this->pe);
    this->is_exe = endswith(this->pe, ".exe");
    this->def_file = this->name + ".def";
    this->def_executor = ExecuteCommand("dumpbin.exe", {this->compute_def_line()});
    this->lib_executor = ExecuteCommand("lib.exe", {this->compute_rename_line()});
}

/**
 * 
 */
std::string LibRename::compute_def_line()
{
    return "/EXPORTS " + this->pe;
}

/**
 * 
 */
int LibRename::computeDefFile()
{
    return this->def_executor.execute(this->def_file);
}

/**
 * 
 */
int LibRename::executeRename()
{
    if(!this->deploy || this->is_exe){
        if(!this->computeDefFile()) {
            return 0;
        }
        if(!this->executeLibRename()) {
            return 0;
        }
    }
    if (this->full || this->is_exe) {
        if(!this->executePERename()) {
            std::cerr << "Unable to execute rename of "
                "referenced components in PE file: " << this->name << "\n";
            return 0;
        }
    }
    return 1;
}

/**
 * 
 */
int LibRename::executeLibRename()
{
    this->lib_executor.execute();
    int ret_code = this->lib_executor.join();
    if(ret_code) {
        std::cerr << GetLastError();
        return ret_code;
    }
    // import library has been generated with
    // mangled abs path to dll -
    // unmangle it
    CoffReaderWriter cr(this->new_lib);
    CoffParser coff(&cr);
    if (!coff.parse()) {
        std::cerr << "Unable to parse\n";
        return 0;
    }
    if(!coff.normalize_name()) {
        std::cerr << "Unable to normalize name\n";
        return 0;
    }
    return 1;
}

/**
 * 
 */
int LibRename::executePERename()
{
    LPCWSTR lib_name = ConvertAnsiToWide(this->pe).c_str();
    HANDLE pe_handle = CreateFileW(lib_name, (GENERIC_READ|GENERIC_WRITE), FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!pe_handle){
        std::stringstream os_error;
        os_error << GetLastError();
        std::cerr << "Unable to acquire file handle: " << os_error.str() << "\n";
        return 0;
    }
    return this->find_dll_and_rename(pe_handle);
}

/* Construct the line needed to produce a new import library
 * given a set of symbols exported by a DLL, the current import lib
 * and a name for said DLL, which in our case is the mangled DLL
 * absolute path. This creates an import libray with a
 * mangled absolute path to the DLL as its DLL name
 * which we then unmangle to produce the "rpath" that
 * will be injected into binaries that link against this
 * 
 * A complete rename line looks something like
 * 
 * -def:foo.def -name:C;|abs|path|to|foo.dll -out:foo.dll-abs.lib foo.lib
 * 
 * If we're replacing the current binary
 * 
 * -def:foo.def -name:C;|abs|path|to|foo.dll -out:foo.dll.abs-name.lib foo.lib
 * 
*/
std::string LibRename::compute_rename_line()
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
