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

void replace_special_characters(char in[], int len)
{
    for (int i = 0; i < len; ++i) {
        if (special_character_to_path.count(in[i]))
            in[i] = special_character_to_path.at(in[i]);
    }
}

void replace_path_characters(char in[], int len)
{
    for (int i = 0; i < len; i++ ) {
        if (path_to_special_characters.count(in[i]))
            in[i] = path_to_special_characters.at(in[i]);
    }
}

void pad_path(char *pth, DWORD str_size, DWORD bsize = MAX_PATH)
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
    pad_path(chr_abs_out, abs_out.length(), MAX_PATH);
    mangled_abs_out = chr_abs_out;
    free(chr_abs_out);
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

CoffReader::CoffReader(std::string file) 
: _file(file) {}

bool CoffReader::Open()
{
    this->pe_stream.open(this->_file, std::ios::in | std::ios::out | std::ios::binary);
    return this->pe_stream.is_open();
}

bool CoffReader::Close()
{
    this->pe_stream.close();
    return !this->pe_stream.is_open();
}

bool CoffReader::isOpen()
{
    return this->pe_stream.is_open();
}

bool CoffReader::isClosed()
{
    return !this->pe_stream.is_open();
}

void CoffReader::read_sig(coff &coff_in)
{
    this->pe_stream.read((char *)&coff_in.signature, IMAGE_ARCHIVE_START_SIZE);
}

void CoffReader::read_header(coff_header& coff_in)
{
    this->pe_stream.read((char*)&coff_in, sizeof(coff_header));
}

void CoffReader::read_member(coff_header& head, coff_member& coff_in)
{
    int member_size(std::stoi(head.file_size));
    this->pe_stream.read((char *)&coff_in, member_size);
}

std::streampos CoffReader::tell()
{
    return this->pe_stream.tellg();
}

void CoffReader::seek(int bytes)
{
    this->pe_stream.seekg(bytes);
    this->pe_stream.seekp(bytes);
}

bool CoffReader::end()
{
    return this->pe_stream.eof();
}

void CoffReader::write_name(char * name, int size)
{
    this->pe_stream.write(name, size);
}

CoffParser::CoffParser(CoffReader * cr)
: coffStream(cr) {}

bool CoffParser::parse()
{
    this->coffStream->read_sig(this->coff_);
    CoffMembers members;
    while(!this->coffStream->end()) {
        coff_entry entry;
        entry.offset = this->coffStream->tell();
        this->coffStream->read_header(entry.header);
        this->coffStream->read_member(entry.header, entry.member);
        members.emplace_back(entry);
    }
    this->coff_.members = members;
    return true;
}

void CoffParser::parse_names()
{
    for (auto mem: this->coff_.members) {
        std::string name_ref(mem.header.file_name);
        if (!endswith(name_ref, "/")) {
            // Name is longer than 16 bytes, need to lookup name in longname offset
            int longname_offset = std::stoi(name_ref.substr(1, std::string::npos));
            std::string name;
            // Longnames member is always the third member if it exists
            // We know it exists at this point due to the success of the conditional above
            // Reconstruct name from location in longnames member
            for (int i = longname_offset; this->coff_.members[2].member.data[i] != '\0'; ++i)
                name += this->coff_.members[2].member.data[i];
            this->names.push_back(name);
        }
        else {
            this->names.push_back(name_ref);
        }
    }
}

bool CoffParser::is_imp_lib()
{
    for (auto name: this->names) {
        if (name.find(".dll") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool CoffParser::normalize_name()
{
    for (auto mem: this->coff_.members) {
        std::string name_ref(mem.header.file_name);

        if (!endswith(name_ref, "/")) {
            // Name is longer than 16 bytes, need to lookup name in longname offset
            int longname_offset = std::stoi(name_ref.substr(1, std::string::npos));
            // Longnames member is always the third member if it exists
            // We know it exists at this point due to the success of the conditional above
            std::vector<char> name;
            // Reconstruct name from location in longnames member
            int i;
            for (i = longname_offset; this->coff_.members[2].member.data[i] != '\0'; ++i)
                name.push_back(this->coff_.members[2].member.data[i]);
            replace_special_characters((char *)&name, i-longname_offset);
            this->coffStream->seek(this->coff_.members[2].offset);
            this->coffStream->seek(longname_offset);
            this->coffStream->write_name(name.data(), name.size());
        }
        else {
            // Supporting relocation requires a padded path, a path short enough
            // to be in the member header indicates a name incompatible
            // with relocation
            throw SpackException("Name too short for relocation");
        }
    }
    return true;
}


bool LibRename::spack_check_for_dll(const std::string &name)
{
    if(this->deploy){
        for(std::map<char, char>::const_iterator it = path_to_special_characters.begin(); it != path_to_special_characters.end(); ++it){
            if(!name.find(it->first) == std::string::npos){
                return true;
            }
        }
        return false;
    }
    else {
        return (!name.find("<!spack>") == std::string::npos);
    }
}

int LibRename::rename_dll(DWORD name_loc, const std::string &dll_name)
{
    if(this->deploy) {
        int padding_len = get_padding_length(dll_name);
        if(padding_len < 8) {
            // path is too long to mark as a Spack path
            // use shorter sigil
            *((LPDWORD) name_loc+2) = (DWORD)"<sp>"; 
        }
        else {
            *((LPDWORD) name_loc+2) = (DWORD)"<!spack>"; 
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
        *((LPDWORD) name_loc) = mangled_padded_new_name.c_str();
    }

}

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
                throw SpackException("Unable to relocate DLL");
            }
        }
    }
    if(!CloseHandle(basepointer)){
        std::cerr << "Unable to properly close file view\n";
        return -3;
    }
    if(!CloseHandle(hMapObject)){
        std::cerr << "Unable to properly close file map\n";
        return -4;
    }
}

LibRename::LibRename(std::string lib, bool full, bool deploy, bool replace)
: replace(replace), full(full), lib(lib), deploy(deploy)
{
    this->name = stem(this->lib);
    this->def_file = this->name + ".def";
    this->def_executor = ExecuteCommand("dumpbin.exe", {this->compute_def_line()});
    this->lib_executor = ExecuteCommand("lib.exe", {this->compute_rename_line()});
}

std::string LibRename::compute_def_line()
{
    return "/EXPORTS " + this->lib;
}

void LibRename::computeDefFile()
{
    this->def_executor.execute(this->def_file);
}

int LibRename::executeRename()
{
    try {
        this->computeDefFile();
        this->executeLibRename();
        if (this->full) {
            this->executeDllRename();
        }
    }
    catch (SpackException &e) {
        std::cerr << e.what() << "\n";
        return -1;
    }
    return 0;
}

void LibRename::executeLibRename()
{
    this->lib_executor.execute();
    // import library has been generated with
    // mangled abs path to dll -
    // unmangle it
    CoffReader cr(this->new_lib);
    CoffParser coff(&cr);
    coff.parse();
    coff.normalize_name();
}


void LibRename::executeDllRename()
{
    LPCWSTR lib_name = ConvertAnsiToWide(this->lib).c_str();
    HANDLE dll_handle = CreateFileW(lib_name, (GENERIC_READ|GENERIC_WRITE), FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!dll_handle){
        std::stringstream os_error;
        os_error << GetLastError();
        throw SpackException(os_error.str());
    }
    this->find_dll_and_rename(dll_handle);
}

std::string LibRename::compute_rename_line()
{
    std::string line("-def:");
    line += this->def_file + " ";
    line += "-name:";
    line += mangle_name(this->lib) + " ";
    std::string name(stem(this->lib));
    if (!this->replace){
        this->new_lib = name + ".abs-name.lib";
    }
    else {
        this->new_lib = this->lib;
    }
    line += "-out:\""+ this->new_lib + "\"" + " " + this->lib;
    return line;
}


char const * WinRPathRenameException::what()
{
    return this->message.c_str();
}
