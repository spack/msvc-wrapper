/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "utils.h"

#include <algorithm>
#include <map>
#include <iostream>
#include <string>
#include <cwchar>
#include <fstream>
#include "shlwapi.h"

//////////////////////////////////////////////////////////
// String helper methods adding cxx20 features to cxx14 //
//////////////////////////////////////////////////////////
/**
 * Returns true of arg starts with match
 */
bool startswith(const std::string &arg, const std::string &match)
{
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(0, matchLen, match) == 0;
}

/**
 * Returns true if arg starts with match
 */
bool startswith(const std::string &arg, const char * match)
{
    return startswith(arg, (std::string)match);
}

/**
 * Returns true if arg ends with match
 */
bool endswith(const std::string &arg, const std::string &match)
{
    size_t matchLen = match.size();
    if ( matchLen > arg.size() )
        return false;
    return arg.compare(arg.size() - matchLen, matchLen, match) == 0;
}

/**
 * Returns true if arg ends with match
 */
bool endswith(const std::string &arg, char const* match)
{
    return endswith(arg, (std::string)match);
}

/**
 * Converts wide strings to ANSI (standard) strings
 * 
 * Converts wstring to string
 */
std::string ConvertWideToANSI(const std::wstring &wstr)
{
    int count = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.length(), NULL, 0, NULL, NULL);
    std::string str(count, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], count, NULL, NULL);
    return str;
}

/**
 * Converts standard strings to wide strings
 * 
 * Converts string to wstring
 */
std::wstring ConvertAnsiToWide(const std::string &str)
{
    int count = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), NULL, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.length(), &wstr[0], count);
    return wstr;
}

/**
 * Decomposes the input string into a list separated by
 * delim
 * 
 * Returns the list produced by breaking up input string s on delim
 */
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

/**
 * Strips substring from the end of input string s
 * 
 * Returns stripped version of s
 */
std::string strip(const std::string &s, const std::string &substr)
{
    if(!endswith(s, substr))
        return s;
    return s.substr(0, s.size()-substr.size());
}

/**
 * Strips substring from the beginning of input string s
 * 
 * Returns stripped version of s
 */
std::string lstrip(const std::string &s, const std::string &substr)
{
    if(!startswith(s, substr))
        return s;
    return s.substr(substr.size()-1, s.size());
}

/**
 * combines list of strings into one string joined on join_char
 */
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

void StripPathAndExe(std::string &command) {
    StripPath(command);
    StripExe(command);
};

void StripExe(std::string &command) {
    // Normalize command to lowercase to avoid parsing issues
    std::transform(command.begin(), command.end(), command.begin(),
        [](unsigned char c){ return std::tolower(c); });
    std::string::size_type loc = command.rfind(".exe");
    if ( std::string::npos != loc )
        command.erase(loc);
}

void StripPath(std::string &command) {
    command.erase(0, command.find_last_of("\\/") + 1);
}


bool CLICheck(const char * arg, const char * check)
{
    std::string normalized_arg(arg);
    StripPathAndExe(normalized_arg);
    return strcmp(normalized_arg.c_str(), check) == 0;
}


bool IsRelocate(const char * arg)
{
    return CLICheck(arg, "relocate");
}

bool IsReport(const char * arg)
{
    return CLICheck(arg, "report");
}

/**
 * Checks if an argument has already been defined on the command line
 */
int redefinedArgCheck(const std::map<std::string, std::string> &args, const char * arg, const char * cli_name)
{
    if ( args.find(arg) != args.end()) {
        std::cerr << "Invalid command line, too many values for argument: " << cli_name << "\n";
        return 1;
    }
    return 0;
}

/**
 * Check for the presense of an argument in the argument map
 */
int checkArgumentPresence(const std::map<std::string, std::string> &args, const char * val, bool required = true)
{
    if (args.find(val) == args.end()) {
        std::cerr << "Warning! Argument (" << val << ") not present";
        if (required) {
            return 0;
        }
    }
    return 1;
}

/**
 * Parse the command line arguments supportin the relocate command
 */
std::map<std::string, std::string> ParseRelocate(const char ** args, int argc) {
    std::map<std::string, std::string> opts;
    for (int i = 0; i < argc; i++){
        if (!strcmp(args[i], "--pe")) {
            if(redefinedArgCheck(opts, "pe", "--pe")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("pe", args[++i]));
        }
        else if (endswith((std::string)args[i], ".dll")) {
            if(redefinedArgCheck(opts, "pe", "pe")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("pe", args[i]));
        }
        else if (endswith((std::string)args[i], ".exe")) {
            if(redefinedArgCheck(opts, "pe", "pe")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("pe", args[i]));
        }
        else if (!strcmp(args[i], "--full")) {
            if(redefinedArgCheck(opts, "full", "--full")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("full", "full"));
        }
        else if (!strcmp(args[i], "--export")) {
            // export and deploy are mutually exclusive, if one is defined
            // the other cannot be
            if(redefinedArgCheck(opts, "export", "--export") 
                || redefinedArgCheck(opts, "deploy", "--deploy")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("cmd", "export"));
        }
        else if (!strcmp(args[i], "--deploy")) {
            // export and deploy are mutually exclusive, if one is defined
            // the other cannot be
            if(redefinedArgCheck(opts, "export", "--export")
               || redefinedArgCheck(opts, "deploy", "--deploy")) {
                opts.clear();
                return opts;
            } 
            opts.insert(std::pair<std::string, std::string>("cmd", "deploy"));
        }
        else {
            // Unknown argument, warn the user it will not be used
            std::cerr << "Unknown argument :" << args[i] << "will be ignored\n";
        }
    }
    if(!checkArgumentPresence(opts, "pe")) {
        opts.clear();
        return opts;
    }
    return opts;
}


std::map<std::string, std::string> ParseReport(int argc, const char** args)
{
    std::map<std::string, std::string> opts;
    for(int i=0; i<argc; ++i){
        if (endswith((std::string)args[i], ".dll")) {
            if(redefinedArgCheck(opts, "pe", "pe")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("pe", args[i]));
        }
        else if (endswith((std::string)args[i], ".exe")) {
            if(redefinedArgCheck(opts, "pe", "pe")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("pe", args[i]));
        }
        else if (endswith((std::string)args[i], ".lib")) {
            if(redefinedArgCheck(opts, "coff", "coff")) {
                opts.clear();
                return opts;
            }
            opts.insert(std::pair<std::string, std::string>("coff", args[i]));
        }
    }
    return opts;
}

/**
 * Given an environment variable name
 * return the corresponding environment variable value
 * or an empty string as appropriate
 */
std::string GetSpackEnv(const char* env) {
    char* envVal = getenv(env);
    return envVal ? envVal : std::string();
}

/**
 * Given an environment variable name
 * return the corresponding environment variable value
 * or an empty string as appropriate
 */
std::string GetSpackEnv(const std::string &env) {
    return GetSpackEnv(env.c_str());
}

/**
 * Returns list of strings from environment variable value
 * representing a list delineated by delim argument
 */
StrList GetEnvList(const std::string &envVar, const std::string &delim) {
    std::string envValue = GetSpackEnv(envVar);
    if (! envValue.empty())
        return split(envValue, delim);
    else
        return StrList();
}

int ValidateSpackEnv() {
    std::vector<std::string> SpackEnv{
"SPACK_ENV_PATH",
"SPACK_DEBUG_LOG_DIR",
// "SPACK_DEBUG_LOG_ID"
"SPACK_COMPILER_SPEC",
// "SPACK_CC_RPATH_ARG"
// "SPACK_CXX_RPATH_ARG"
// "SPACK_F77_RPATH_ARG"
// "SPACK_FC_RPATH_ARG"
// "SPACK_LINKER_ARG"
// "SPACK_SHORT_SPEC"
"SPACK_SYSTEM_DIRS",
"SPACK_CC",
"SPACK_LD",};
    for(auto &var: SpackEnv)
        if(!getenv(var.c_str())){
            std::cerr << var + " isn't set in the environment and is expected to be\n";
            return 0;
        }
    return 1;
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
    std::cout << "     To preform relocation, invoke the 'relocate' symlink to this file:\n";
    std::cout << "\n";
    std::cout << "      Options:\n";
    std::cout << "          [--pe] <path to pe file>                     = PE file to be relocated\n";
    std::cout << "          --full                                       = Relocate dynamic references inside\n";
    std::cout << "                                                          the dll in addition to re-generating\n";
    std::cout << "                                                          the import library\n";
    std::cout << "                                                          Note: this is assumed to be true if\n";
    std::cout << "                                                           relocating an executable.\n";
    std::cout << "                                                          If an executable is relocated, no import\n";
    std::cout << "                                                          library operations are performed.\n";
    std::cout << "          --export|--deploy                             = Mutually exclusive command modifier.\n";
    std::cout << "                                                           Instructs relocate to either prepare the\n";
    std::cout << "                                                           dynamic library for exporting to build cache\n";
    std::cout << "                                                           or for extraction from bc onto new host system\n";
    std::cout << "          --report                                      = Report information about the parsed PE/Coff files\n";
    std::cout << "\n";
    std::cout << "     To report on PE/COFF files, invoke the 'reporter' symlink to this executable or use the --report flag when invoking 'relocate'";
    std::cout << "\n";
    std::cout << "     Options:\n";
    std::cout << "         <path to file>                                 = Path to any PE or COFF file\n";
    std::cout << "\n";
    return true;
}

bool CheckAndPrintHelp(const char ** arg, int argc)
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

std::string basename(const std::string &file)
{
    std:size_t last_path = file.find_last_of("\\")+1;
    if (last_path == std::string::npos) {
        return std::string();
    }
    return file.substr(last_path);
}

std::string GetCWD()
{
    DWORD buf_size;
    buf_size = GetCurrentDirectoryW(0, NULL);
    wchar_t * w_cwd = new wchar_t[buf_size];
    GetCurrentDirectoryW(buf_size, w_cwd);
    std::wstring ws_cwd(w_cwd);
    free(w_cwd);
    return ConvertWideToANSI(ws_cwd);
}

bool IsPathAbsolute(const std::string &pth)
{
    return !PathIsRelativeA(pth.c_str());
}

/**
 * Determines the file offset on disk from the relative virtual address of a given section
 * header
 */
DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER &section_header, DWORD number_of_sections, DWORD rva) {

    for (int i = 0; i < number_of_sections; ++i, ++section_header) {
        DWORD sectionStartRVA = section_header->VirtualAddress;
        DWORD sectionEndRVA = sectionStartRVA + section_header->SizeOfRawData;
        // check section bounds for RVA
        if (rva >= sectionStartRVA && rva < sectionEndRVA) {
            DWORD fileOffset = rva - sectionStartRVA + section_header->PointerToRawData;
            return fileOffset;
        }
    }
    std::cerr << "Error: RVA 0x" << std::hex << rva << " not found in any section." << std::endl;
    return 0;
}

LibraryFinder::LibraryFinder() : search_vars{"SPACK_RELOCATE_PATH"} {}

std::string LibraryFinder::FindLibrary(const std::string &lib_name, const std::string &lib_path) {
    // Read env variables and split into paths
    // Only ever run once
    // First check if lib is absolute path
    if (this->IsSystem(lib_path)) {
        return std::string();
    }
    // next search the CWD
    std::string cwd(GetCWD());
    auto res = this->Finder(cwd, lib_name);
    if (!res.empty())
        return res;
    this->EvalSearchPaths();
    if (this->evald_search_paths.empty()) {
        return std::string();
    }
    // next search env variable paths
    for (std::string var: this->search_vars) {
        std::vector<std::string> searchable_paths = this->evald_search_paths.at(var);
        for (std::string pth: searchable_paths) {
            auto res = this->Finder(pth, lib_name);
            if (!res.empty())
                return res;
        }
    }
    return std::string();
}

void LibraryFinder::EvalSearchPaths() {
    if (!this->evald_search_paths.empty())
        return;
    for (std::string var: this->search_vars) {
        std::string envVal = GetSpackEnv(var.c_str());
        if (!envVal.empty())
            this->evald_search_paths[var] = split(envVal, ";");
    }
}

std::string LibraryFinder::Finder(const std::string &pth, const std::string &lib_name) {
    WIN32_FIND_DATAW findFileData;
    std::string searcher = pth + "\\*";
    HANDLE hFind = FindFirstFileW(ConvertAnsiToWide(searcher).c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "FindFirstFile failed (" << GetLastError() << ")" << std::endl;
        return std::string();
    }
    
    do {
        if (std::wcsstr(findFileData.cFileName, ConvertAnsiToWide(lib_name).c_str())){
            return pth + "\\" + ConvertWideToANSI(findFileData.cFileName);
        }
    } while (FindNextFileW(hFind, &findFileData));

    DWORD dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES) {
        std::cerr << "FindNextFile failed (" << dwError << ")" << std::endl;
    }
    FindClose(hFind);
    return std::string();
        
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
    "system32",
    "KERNEL32",
    "WS2_32",
    "dbghelp",
    "bcrypt",
    "ADVAPI32",
    "SHELL32",
    "CRYPT32",
    "USER32",
    "ole32",
    "OLEAUTH32"
};

bool LibraryFinder::IsSystem(const std::string &pth) {
    for (auto loc: system_locations) {
        if (pth.find(loc) != std::string::npos) {
            return true;
        }
    }
    return false;
}

int SafeHandleCleanup(HANDLE &handle)
{
    if(handle != INVALID_HANDLE_VALUE){
        if ( !CloseHandle(handle) ) {
            return 0;
        }
    }
    return 1;
}

DWORD ToLittleEndian(DWORD val)
{
    DWORD little_endian_val = (val >> 24) | 
    ((val & 0x00FF0000) >> 8) | 
    ((val & 0x0000FF00) << 8) | 
    (val << 24);
    return little_endian_val;
}

char * findstr(char *search_str, const char * substr, int size)
{
    char * search = search_str;
    int str_size = strlen(substr);
    while (search < search_str+size) {
        if (!strncmp(search, substr, str_size)) {
            return search;
        }
        ++search;
    }
    return NULL;
}
