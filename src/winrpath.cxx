#pragma once
#include "winrpath.h"
#include "utils.h"

#include <sstream>

#define BUFSIZE 4096

using CoffMembers = std::vector<coff_entry>;


LinkerInvocation::LinkerInvocation(const std::string &linkLine): line(linkLine), is_exe(true) {
    StrList tokenized_line = split(this->line, " ");
    this->tokens = tokenized_line;

}

LinkerInvocation::LinkerInvocation(const StrList &linkLine) {
    this->tokens = linkLine;
    this->line = join(linkLine);
}

void LinkerInvocation::parse() {
    for (auto token = this->tokens.begin(); token != this->tokens.end(); ++token) {
        if (endswith(*token, ".lib")) {
            this->libs.push_back(*token);
        }
        else if (startswith(*token, "-name") || startswith(*token, "/name")) {
            this->name = split(*token, ":")[1];
        }
        else if (*token == "/dll") {
            this->is_exe = false;
        }
        else if (startswith(*token, "-out") || startswith(*token, "/out")) {
            this->output = split(*token, ":")[1];
        }
    }
}

std::string LinkerInvocation::get_name()
{
    return this->name;
}

bool LinkerInvocation::is_exe_link() {
    return this->is_exe || endswith(this->output, ".exe");
}

CoffReader::CoffReader(std::string file) : _file(file) {}

bool CoffReader::Open() {
    this->pe_stream.open(this->_file, std::ios::in | std::ios::out | std::ios::binary);
    return this->pe_stream.is_open();
}

bool CoffReader::Close() {
    this->pe_stream.close();
    return !this->pe_stream.is_open();
}

bool CoffReader::isOpen() {
    return this->pe_stream.is_open();
}

bool CoffReader::isClosed() {
    return !this->pe_stream.is_open();
}

void CoffReader::read_sig(char * sig) {
    this->pe_stream.read(sig, IMAGE_ARCHIVE_START_SIZE);
}

void CoffReader::read_header(coff_header * coff_in) {
    this->pe_stream.read((char*)coff_in, sizeof(coff_header));
}

void CoffReader::read_member(coff_header head, coff_member * coff_in) {
    int member_size(std::stoi(head.file_size));
    this->pe_stream.read(coff_in->data, member_size);
}

std::streampos CoffReader::tell() {
    return this->pe_stream.tellg();
}

void CoffReader::seek(int bytes=-1) {
    this->pe_stream.seekg(bytes);
    this->pe_stream.seekp(bytes);
}

bool CoffReader::end() {
    return this->pe_stream.eof();
}

void CoffReader::write_name(char * name, int size) {
    this->pe_stream.write(name, size);
}

CoffParser::CoffParser(CoffReader * cr) : coffStream(cr) {}

bool CoffParser::parse() {
    this->coffStream->read_sig(this->coff_.signature);
    CoffMembers members;
    while(!this->coffStream->end()) {
        coff_entry entry;
        entry.offset = this->coffStream->tell();
        this->coffStream->read_header(&entry.header);
        this->coffStream->read_member(entry.header, &entry.member);
        members.emplace_back(entry);
    }
    this->coff_.members = members;
}

void CoffParser::parse_names() {
    for (auto mem: this->coff_.members) {
        std::string name_ref(mem.header.file_name);
        if (!endswith(name_ref, "/")) {
            // Name is longer than 16 bytes, need to lookup name in longname offset
            int longname_offset = std::stoi(name_ref.substr(1, std::string::npos));
            // Longnames member is always the third member if it exists
            // We know it exists at this point due to the success of the conditional above
            std::string name;
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

bool CoffParser::is_imp_lib() {
    for (auto name: this->names) {
        if (name.find(".dll") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool CoffParser::normalize_name() {
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
            this->coffStream->seek(mem.offset);
            this->coffStream->seek(longname_offset);
            this->coffStream->write_name(name.data(), name.size());
        }
        else {
            replace_special_characters(mem.header.file_name, 16);
            this->coffStream->seek(mem.offset);
            this->coffStream->write_name(mem.header.file_name, 16);
        }
    }
}

const std::map<char, char> special_character_to_path{
    {'|', '\\'},
    {';', ':'}
};

const std::map<char, char> path_to_special_characters{
    {'\\', '|'},
    {'/', '|'},
    {':', ';'}
};

void replace_special_characters(char in[], int len) {
    for (int i = 0; i < len; ++i) {
        if (special_character_to_path.count(in[i]))
            in[i] = special_character_to_path.at(in[i]);
    }
}

void replace_path_characters(char in[], int len) {
    for (int i = 0; i < len; i++ ) {
        if (path_to_special_characters.count(in[i]))
            in[i] = path_to_special_characters.at(in[i]);
    }
}

LibRename::LibRename(std::string lib, std::string name, bool replace) : replace(replace), lib(lib), name(name) {
    this->def_file = std::filesystem::path(this->lib).stem().string() + ".def";
    this->def_executor = ExecuteCommand("dumpbin.exe", this->compute_def_line());
    this->lib_executor = ExecuteCommand("lib.exe", this->compute_rename_line());
}

std::string LibRename::compute_def_line() {
    return "/EXPORTS " + this->name + ".dll";
}


void LibRename::computeDefFile()
{
    this->def_executor.execute(this->def_file);
}

void LibRename::executeLibRename()
{
    this->lib_executor.execute();
}

std::string LibRename::compute_rename_line() {
    std::string line("-def:");
    line += this->def_file + " ";
    line += "-name:";
    line += this->name + " ";
    std::string name(std::filesystem::path(this->lib).stem().string());
    if (!this->replace)
        this->new_lib = name + "abs-name.lib";
    else
        this->new_lib = this->lib;
    line += "-out:\""+ this->new_lib + "\"" + " " + this->lib;
    return line;
}

LibraryFinder::LibraryFinder() : search_vars{"LINK", "LIB", "PATH", "TMP"} {}

std::string LibraryFinder::find_library(std::string lib_name) {
    // Read env variables and split into paths
    // Only ever run once
    // First check if lib is absolute path
    std::filesystem::path lib_path(lib_name);
    if (this->is_system(lib_name)) {
        return std::string();
    }
    if (lib_path.is_absolute())
        return lib_path.string();
    // next search the CWD
    std::filesystem::path cwd(std::filesystem::current_path());
    auto res = this->finder(cwd);
    if (!res.empty())
        return res.string();
    this->eval_search_paths();
    // next search env variable paths
    for (std::string var: this->search_vars) {
        std::vector<std::string> searchable_paths = this->evald_search_paths.at(var);
        for (std::string pth: searchable_paths) {
            auto res = this->finder(pth);
            if (!res.empty())
                return res.string();
        }
    }
}

void LibraryFinder::eval_search_paths() {
    if (!this->evald_search_paths.empty())
        return;
    for (std::string var: this->search_vars) {
        std::string envVal = getenv(var.c_str());
        if (!envVal.empty())
            this->evald_search_paths[var] = split(envVal, ";");
    }
}

std::filesystem::path LibraryFinder::finder(std::filesystem::path pth) {
    for (auto const& dir_entry: std::filesystem::directory_iterator{pth}) {
        auto candidate_file = dir_entry.path() / pth;
        if (std::filesystem::exists(candidate_file))
            return candidate_file;
    }
}

std::filesystem::path LibraryFinder::finder(std::string pth) {
    this->finder(std::filesystem::path(pth));
}

std::vector<std::string> system_locations = {
    "api-ms-",
    "ext-ms-",
    "ieshims",
    "emclient",
    "devicelock",
    "wpax",
    "azure",
    "vcruntime",
    "msvc",
    "WINDOWS",
    "system32"
};

bool LibraryFinder::is_system(std::string pth) {
    for (auto loc: system_locations) {
        if (pth.find(loc) != std::string::npos) {
            return true;
        }
    }
}

char const * WinRPathRenameException::what() {
    return this->message.c_str();
}
