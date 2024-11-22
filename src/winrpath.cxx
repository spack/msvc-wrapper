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

void CoffReader::seek(int bytes) {
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
    return true;
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
    return true;
}

LibRename::LibRename(std::string lib, std::string name, bool replace) : replace(replace), lib(lib), name(name) {
    this->def_file = stem(this->lib) + ".def";
    this->def_executor = ExecuteCommand("dumpbin.exe", {this->compute_def_line()});
    this->lib_executor = ExecuteCommand("lib.exe", {this->compute_rename_line()});
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
    std::string name(stem(this->lib));
    if (!this->replace)
        this->new_lib = name + "abs-name.lib";
    else
        this->new_lib = this->lib;
    line += "-out:\""+ this->new_lib + "\"" + " " + this->lib;
    return line;
}

char const * WinRPathRenameException::what() {
    return this->message.c_str();
}
