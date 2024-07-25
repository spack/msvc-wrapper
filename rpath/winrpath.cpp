#pragma once
#include <sstream>
#include "winrpath.h"

#define BUFSIZE 4096

using StrLst = std::vector<std::string>;
using CoffMembers = std::vector<coff_entry>;

// String helper methods adding cxx20 features to cxx14
bool startswith(std::string &arg, std::string &match) {
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(0, matchLen, match) == 0;
}

bool startswith(std::string &arg, const char * match) {
    return startswith(arg, (std::string)match);
}

bool endswith(std::string &arg, char const* match) {
    return endswith(arg, (std::string)match);
}

bool endswith(std::string &arg, std::string &match) {
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(arg.size() - matchLen, matchLen, match) == 0;
}

std::string ConvertWideToANSI(const std::wstring &wstr) {
    int count = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string str(count, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
    return str;
}

std::wstring ConvertAnsiToWide(const std::string &str) {
    int count = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), NULL, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), &wstr[0], count);
    return wstr;
}

StrLst split(std::string s, std::string delim) {
    size_t pos = 0, start = 0;
    std::string token;
    StrLst res = StrLst();
    for (;;) {
        pos = s.find(delim, start);
        token = s.substr(start, pos-start);
        start = pos+1;
        if (token == delim || token.empty()) {
            continue;
        }
        res.push_back(token);
        if (pos == std::string::npos) {
            break;
        }
    }
    return res;
}

LinkerInvocation::LinkerInvocation(std::string linkLine): line(linkLine) {
    this->is_exe = true;
    this->libs = StrLst();
    this->tokens = StrLst();
}

void LinkerInvocation::parse() {

    StrLst tokenized_line = split(this->line, " ");
    this->tokens = tokenized_line;
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
        members.push_back(entry);
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

void LibRename::setupExecute() {
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOW siStartInfo;
    ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );

    // Set up members of the STARTUPINFO structure.
    // This structure specifies the STDIN and STDOUT handles for redirection.
    ZeroMemory( &siStartInfo, sizeof(STARTUPINFOW) );
    siStartInfo.cb = sizeof(STARTUPINFOW);
    siStartInfo.hStdError = this->ChildStdOut_Wd;
    siStartInfo.hStdOutput = this->ChildStdOut_Wd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    this->procInfo = piProcInfo;
    this->startInfo= siStartInfo;
}

bool LibRename::pipeChildtoStdOut() {
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = TRUE;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    for (;;)
    {
        bSuccess = ReadFile( this->ChildStdOut_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break;

        bSuccess = WriteFile(hParentStdOut, chBuf,
                            dwRead, &dwWritten, NULL);
        if (! bSuccess ) break;
    }
    return bSuccess;
}


std::string LibRename::pipeChildToString() {
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    std::string out;
    bool bSuccess;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    for (;;)
    {
        bSuccess = ReadFile( this->ChildStdOut_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break;

        out = std::string(chBuf);
    }
    return out;
}

LibRename::LibRename(std::string lib, std::string name, bool replace) : replace(replace), lib(lib), name(name) {
    this->def_file = std::filesystem::path(this->lib).stem().string() + ".def";
}


std::string LibRename::compute_def_line() {
    return "/EXPORTS " + this->name + ".dll";
}

void LibRename::computeDefFile() {
    LPVOID lpMsgBuf;
    wchar_t * commandline = &ConvertAnsiToWide(this->compute_def_line())[0];
    if(! CreateProcessW(
        ConvertAnsiToWide("dumpbin.exe").c_str(),
        commandline,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &this->startInfo,
        &this->procInfo)
    )
        // Handle errors coming from creating of child proc
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL
        );
        throw WinRPathRenameException((char *)lpMsgBuf);
    // We've suceeded in kicking off the toolchain run
    // Explicitly close write handle to child proc stdout
    // as it is no longer needed and if we do not then cannot
    // determine when child proc is done
    CloseHandle(this->ChildStdOut_Wd);
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

void LibRename::executeLibRename() {
    LPVOID lpMsgBuf;
    wchar_t * commandline = &ConvertAnsiToWide(this->compute_rename_line())[0];
    if(! CreateProcessW(
        ConvertAnsiToWide("lib.exe").c_str(),
        commandline,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &this->startInfo,
        &this->procInfo)
    )
        // Handle errors coming from creating of child proc
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL
        );
        throw WinRPathRenameException((char *)lpMsgBuf);
    // We've suceeded in kicking off the toolchain run
    // Explicitly close write handle to child proc stdout
    // as it is no longer needed and if we do not then cannot
    // determine when child proc is done
    CloseHandle(this->ChildStdOut_Wd);
}

void LibRename::createChildPipes() {
    SECURITY_ATTRIBUTES saAttr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if( !CreatePipe(&this->ChildStdOut_Rd, &this->ChildStdOut_Wd, &saAttr, 0) )
        throw WinRPathRenameException("Could not create Child Pipe");
    if ( !SetHandleInformation(ChildStdOut_Rd, HANDLE_FLAG_INHERIT, 0) )
        throw WinRPathRenameException("Child pipe handle inappropriately inhereited");
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
    "msvc"
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
