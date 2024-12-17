#include "utils.h"

#include <map>
#include <iostream>
#include <string>
#include <cwchar>
#include <fstream>
#include "shlwapi.h"


// String helper methods adding cxx20 features to cxx14
bool startswith(const std::string &arg, const std::string &match)
{
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(0, matchLen, match) == 0;
}

bool startswith(const std::string &arg, const char * match)
{
    return startswith(arg, (std::string)match);
}

bool endswith(const std::string &arg, const std::string &match)
{
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(arg.size() - matchLen, matchLen, match) == 0;
}

bool endswith(const std::string &arg, char const* match)
{
    return endswith(arg, (std::string)match);
}

std::string ConvertWideToANSI(const std::wstring &wstr)
{
    int count = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string str(count, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
    return str;
}

std::wstring ConvertAnsiToWide(const std::string &str)
{
    int count = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), NULL, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), &wstr[0], count);
    return wstr;
}

StrList split(const std::string &s, const std::string &delim)
{
    size_t pos_start = 0, pos_end;
    size_t delim_len = delim.length();
    std::string token;
    StrList res = StrList();

    while ( (pos_end = s.find(delim, pos_start)) != std::string::npos ) {
        size_t token_len = pos_end - pos_start;
        token = s.substr(pos_start, token_len);
        pos_start = pos_end + delim_len;
        if (token == delim || token.empty())
        {
            continue;
        }
        res.push_back(token);
    }
    res.push_back(s.substr(pos_start));
    return res;
}

std::string strip(const std::string &s, const std::string &substr)
{
    if(!endswith(s, substr))
        return s;
    return s.substr(0, s.size()-substr.size());
}

std::string lstrip(const std::string &s, const std::string &substr)
{
    if(!startswith(s, substr))
        return s;
    return s.substr(substr.size()-1, s.size());
}

std::string join(const StrList &args, const std::string &join_char)
{
    std::string joined_path;
    for(std::string arg : args) {
       joined_path += arg + join_char;
    }
    // Remove trailing space
    joined_path.pop_back();
    return joined_path;
}

std::string getCmdOption(char ** begin, char ** end, const std::string & option)
{
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return std::string(*itr);
    }
    return 0;
}

bool isRelocate(const char * arg)
{
    return strcmp(arg, "relocate") == 0;
}


void redefinedArgCheck(const std::map<std::string, std::string> &args, const char * arg, const char * cli_name)
{
    if ( args.find(arg) != args.end()) {
        char * error_line = strcat("Invalid command line, too many values for argument: ", cli_name);
        throw SpackException(error_line);
    }
}

void checkArgumentPresence(const std::map<std::string, std::string> &args, const char * val, bool required = true)
{
    if (args.find(val) == args.end()) {
        if (required) {
            throw SpackException(strcat("Required argument not present", val));
        }
        else {
            std::cout << "Warning! Argument (" << val << ") not present";
        }
    }
}

std::map<std::string, std::string> parseRelocate(const char ** args, int argc) {
    std::map<std::string, std::string> opts;
    for (int i = 0; i < argc; i++){
        if (strcmp(args[i], "--library")) {
            redefinedArgCheck(opts, "lib", "--library");
            opts.insert(std::pair<std::string, std::string>("lib", args[++i]));
        }
        else if (endswith((std::string)args[i], ".dll")) {
            redefinedArgCheck(opts, "lib", "lib");
            opts.insert(std::pair<std::string, std::string>("lib", args[i]));
        }
        else if (strcmp(args[i], "--full")) {
            redefinedArgCheck(opts, "full", "--full");
            opts.insert(std::pair<std::string, std::string>("full", std::string("full")));
        }
        else {
            // Unknown argument, warn the user it will not be used
            std::cerr << "Unknown argument :" << args[i] << "will be ignored\n";

        }
    }
    if(!opts.count("full"))
    {
        opts.insert(std::pair<std::string, std::string>("full", std::string("")));
    }
    checkArgumentPresence(opts, "lib");
    checkArgumentPresence(opts, "full");
    return opts;
}


std::string getSpackEnv(const char* env) {
    char* envVal = getenv(env);
    return envVal ? envVal : std::string();
}

std::string getSpackEnv(const std::string &env) {
    return getSpackEnv(env.c_str());
}

StrList getenvlist(const std::string &envVar, const std::string &delim) {
    std::string envValue = getSpackEnv(envVar);
    if (! envValue.empty())
        return split(envValue, delim);
    else
        return StrList();
}

char const* SpackException::what() {
    return this->message.c_str();
}

char const * SpackUnknownCompilerException::what() {
    std::string msg = "Unknown compiler" + this->message;
    return msg.c_str();
}

char const * SpackCompilerException::what() {
    std::string msg = "[spack cc] ERROR " + this->message;
    return msg.c_str();
}

char const * SpackCompilerContextException::what() {
    std::string msg = "Spack compiler must be run from Spack! Missing input: " + this->message;
    return msg.c_str();
}

void validate_spack_env() {
    std::vector<std::string> SpackEnv{
"SPACK_ENV_PATH"
"SPACK_DEBUG_LOG_DIR"
"SPACK_DEBUG_LOG_ID"
"SPACK_COMPILER_SPEC"
"SPACK_CC_RPATH_ARG"
"SPACK_CXX_RPATH_ARG"
"SPACK_F77_RPATH_ARG"
"SPACK_FC_RPATH_ARG"
"SPACK_LINKER_ARG"
"SPACK_SHORT_SPEC"
"SPACK_SYSTEM_DIRS"};
    for(auto &var: SpackEnv)
        if(!getenv(var.c_str())){
            throw SpackCompilerContextException(var + " isn't set in the environment and is expected to be");
        }
}

void die(std::string &cli ) {
    throw SpackCompilerException(cli);
}


bool print_help()
{
    std::cout << "Spack's Windows compiler wrapper\n";
    std::cout << "Version: " << STRING(MSVC_WRAPPER_VERSION) <<"\n";
    std::cout << "\n";
    std::cout << "  Description:\n";
    std::cout << "      This compiler wrapper abstacts the functions \n";
    std::cout << "      of the MSVC and Intel C/C++/Fortran compilers and linkers.\n";
    std::cout << "      This wrapper modifies compilation and link time behavior by\n";
    std::cout << "      injecting Spack specific paths, flags, and arguments to the\n";
    std::cout << "      compiler and linker lines.\n";
    std::cout << "      Link operations are amended to inject the absolute path to\n";
    std::cout << "      a package's dll in its import library, allowing for RPATH\n";
    std::cout << "      like link behavior.\n";
    std::cout << "      Spack's Windows RPaths can be relocated by this wrapper\n";
    std::cout << "      by invoking the 'relocate' form with the proper arguments\n";
    std::cout << "\n\n";
    std::cout << "  Useage:\n";
    std::cout << "      To use this as a compiler/linker wrapper, simply invoke the compiler/linker\n";
    std::cout << "      as normal, with the properly named link to this wrapper in the PATH\n";
    std::cout << "      In this case, the CLI of this wrapper is identical to cl|ifx|link.\n";
    std::cout << "      See https://learn.microsoft.com/en-us/cpp/build/reference/c-cpp-building-reference\n";
    std::cout << "\n";
    std::cout << "      cl.exe /c foo.c";
    std::cout << "\n";
    std::cout << "      To preform relocation, invoke the 'relocate' symlink to this file:\n";
    std::cout << "\n";
    std::cout << "      options:";
    std::cout << "          [--library] <path to library>                = Dynamic library to be relocated\n";
    std::cout << "          --full                                       = Relocate dynamic references inside\n";
    std::cout << "                                                         the dll in addition to re-generating\n";
    std::cout << "                                                         the import library\n";
    std::cout << "\n";
    return true;
}

bool checkAndPrintHelp(const char ** arg, int argc)
{
    if(argc < 2) {
        return print_help();
    }
    else if(strcmp(arg[1], "--help") == 0 || strcmp(arg[1], "-h") == 0)
    {
        return print_help();
    }
    return false;

}

std::string stem(const std::string &file)
{
    std::size_t last_dot = file.find_last_of('.');
    if (last_dot == std::string::npos) {
        return file;
    }
    return file.substr(0, last_dot);
}

std::string getCWD()
{
    DWORD buf_size;
    buf_size = GetCurrentDirectoryW(0, NULL);
    wchar_t * w_cwd = new wchar_t[buf_size];
    GetCurrentDirectoryW(buf_size, w_cwd);
    std::wstring ws_cwd(w_cwd);
    free(w_cwd);
    return ConvertWideToANSI(ws_cwd);
}

bool isPathAbsolute(const std::string &pth)
{
    return !PathIsRelativeA(pth.c_str());
}


DWORD RvaToFileOffset(std::ifstream file, DWORD rva) {
    if (!file.is_open()) {
        std::cerr << "Error: File is not open" << std::endl;
        return 0;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(ntHeaders));

     IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)((char*)&ntHeaders + sizeof(ntHeaders));
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        DWORD sectionStartRVA = sectionHeader->VirtualAddress;
        DWORD sectionEndRVA = sectionStartRVA + sectionHeader->SizeOfRawData;

        if (rva >= sectionStartRVA && rva < sectionEndRVA) {
            DWORD fileOffset = rva - sectionStartRVA + sectionHeader->PointerToRawData;
            file.close();
            return fileOffset;
        }
         sectionHeader++;
    }

    std::cerr << "Error: RVA 0x" << std::hex << rva << " not found in any section." << std::endl;
    file.close();
    return 0;
}

LibraryFinder::LibraryFinder() : search_vars{"LINK", "LIB", "PATH", "TMP"} {}

std::string LibraryFinder::find_library(const std::string &lib_name) {
    // Read env variables and split into paths
    // Only ever run once
    // First check if lib is absolute path
    if (this->is_system(lib_name)) {
        return std::string();
    }
    if (!PathIsRelativeW(ConvertAnsiToWide(lib_name).c_str()))
        return lib_name;
    // next search the CWD
    std::string cwd(getCWD());
    auto res = this->finder(cwd, lib_name);
    if (!res.empty())
        return res;
    this->eval_search_paths();
    // next search env variable paths
    for (std::string var: this->search_vars) {
        std::vector<std::string> searchable_paths = this->evald_search_paths.at(var);
        for (std::string pth: searchable_paths) {
            auto res = this->finder(pth, lib_name);
            if (!res.empty())
                return res;
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

std::string LibraryFinder::finder(const std::string &pth, const std::string &lib_name) {
        WIN32_FIND_DATA findFileData;
        HANDLE hFind = FindFirstFileW(ConvertAnsiToWide(pth).c_str(), &findFileData);

        if (hFind == INVALID_HANDLE_VALUE) {
            std::cerr << "FindFirstFile failed (" << GetLastError() << ")" << std::endl;
            return;
        }
        
        do {
            if (std::wcsstr(findFileData.cFileName, ConvertAnsiToWide(lib_name).c_str())){
                return ConvertWideToANSI(findFileData.cFileName);
            }
        } while (FindNextFile(hFind, &findFileData) != 0);

        DWORD dwError = GetLastError();
        if (dwError != ERROR_NO_MORE_FILES) {
            std::cerr << "FindNextFile failed (" << dwError << ")" << std::endl;
        }
        FindClose(hFind);
}

std::vector<std::string> system_locations = {
    "api-ms-",
    "ext-ms-",
    "ieshims",
    "emclient",
    "devicelock",
    "wpax",
    "vcruntime",
    "WINDOWS",
    "system32"
};

bool LibraryFinder::is_system(const std::string &pth) {
    for (auto loc: system_locations) {
        if (pth.find(loc) != std::string::npos) {
            return true;
        }
    }
}
