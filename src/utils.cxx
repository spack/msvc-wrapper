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
#include <regex>

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
    // Remove trailing token
    const size_t last_token_pos = joined_path.rfind(join_char);
    if(last_token_pos != std::string::npos)
    {
        joined_path.erase(last_token_pos, joined_path.length());
    }
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
    lower(command);
    std::string::size_type loc = command.rfind(".exe");
    if ( std::string::npos != loc && loc + 4 == command.length() )
        command.erase(loc);
}

void StripPath(std::string &command) {
    command.erase(0, command.find_last_of("\\/") + 1);
}

/**
 * Converts a string to lowercase
 * 
 * \arg str - string to be made lowercase
 */
void lower(std::string &str) {
    std::transform(str.begin(), str.end(), str.begin(),
        [](unsigned char c){ return std::tolower(c); });
}


std::string quoteAsNeeded(std::string &str) {
    if (str.find_first_of(" &<>|()") != std::string::npos) {
        // There are spaces or special characters in string, quote it
        return "\"" + str + "\"";
    }
    if (str.find_first_of("\"") != std::string::npos) {
        // If there are escaped quotes in input
        // We need to escape them as well as we're adding another
        // layer of indirection between builder and compiler
        std::regex pattern("\"");
        return std::regex_replace(str, pattern, "\\\"");
    }
    return str;
}


void quoteList(StrList &args) {
    std::transform(args.begin(), args.end(), args.begin(), quoteAsNeeded);
}


std::regex_constants::syntax_option_type composeRegexOptions(const std::vector<std::regex_constants::syntax_option_type> &opts)
{    
    std::regex_constants::syntax_option_type composedOpt;
    if(opts.empty()) {
        // Default option
        composedOpt = std::regex_constants::syntax_option_type::ECMAScript;
    }
    for (std::regex_constants::syntax_option_type opt: opts){
        composedOpt |= opt;
    }
    return composedOpt;
}


std::regex_constants::match_flag_type composeMatchTypes(const std::vector<std::regex_constants::match_flag_type> &flags)
{
    std::regex_constants::match_flag_type composedFlag;
    if(flags.empty()) {
        // Default option
        composedFlag = std::regex_constants::match_flag_type::match_default;
    }
    for (std::regex_constants::match_flag_type flag: flags){
        composedFlag |= flag;
    }
    return composedFlag;
}

std::string regexSearch(
    const std::string &searchDomain, 
    const std::string &regex, 
    const std::vector<std::regex_constants::syntax_option_type> &opts, 
    const std::vector<std::regex_constants::match_flag_type> &flags
)
{
    std::string resultStr;
    std::regex_constants::syntax_option_type opt = composeRegexOptions(opts);
    std::regex_constants::match_flag_type flag = composeMatchTypes(flags);
    std::regex reg(regex, opt);
    std::smatch match;
    if(!std::regex_search(searchDomain, match, reg, flag)){
        resultStr = std::string();
    }
    else {
        resultStr = match.str();
    }
    return resultStr;
}


std::string regexMatch(
    const std::string &searchDomain,
    const std::string &regex, 
    const std::vector<std::regex_constants::syntax_option_type> &opts,
    const std::vector<std::regex_constants::match_flag_type> &flags
)
{
    std::string resultStr;
    std::regex_constants::syntax_option_type opt = composeRegexOptions(opts);
    std::regex_constants::match_flag_type flag = composeMatchTypes(flags);
    std::regex reg(regex, opt);
    std::smatch match;
    if(!std::regex_match(searchDomain, match, reg, flag)){
        resultStr = std::string();
    }
    else {
        resultStr = match.str();
    }
    return resultStr;
}


std::string regexReplace(
    const std::string &replaceDomain, 
    const std::string &regex, 
    const std::string &replacement, 
    const std::vector<std::regex_constants::syntax_option_type> &opts,
    const std::vector<std::regex_constants::match_flag_type> &flags
)
{
    std::regex_constants::syntax_option_type opt = composeRegexOptions(opts);
    std::regex_constants::match_flag_type flag = composeMatchTypes(flags);
    std::regex reg(regex, opt);
    return std::regex_replace(replaceDomain, reg, replacement);   
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

bool ValidateSpackEnv() {
    std::vector<std::string> SpackEnv{
"SPACK_COMPILER_WRAPPER_PATH",
"SPACK_DEBUG_LOG_DIR",
"SPACK_DEBUG_LOG_ID",
"SPACK_SHORT_SPEC",
"SPACK_SYSTEM_DIRS",
"SPACK_MANAGED_DIRS"};
    for(auto &var: SpackEnv)
        if(!getenv(var.c_str())){
            std::cerr << var + " isn't set in the environment and is expected to be\n";
            return false;
        }
    return true;
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
        return file;
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


void debug(std::string dbgStmt) {
    if (DEBUG || getenv("SPACK_DEBUG_WRAPPER")) {
        std::cout << "DEBUG: " << dbgStmt << "\n";
    }
}

void debug(char * dbgStmt, int len) {
    debug(std::string(dbgStmt, len));
}

bool isCommandArg(const std::string &arg, const std::string &command)
{
    const std::string slash_opt = "/"+command;
    const std::string dash_opt = "-"+command;
    return startswith(arg, slash_opt) || startswith(arg, dash_opt);
}

void normalArg(std::string &arg)
{
    // first normalize capitalization
    lower(arg);
    // strip leading / and -
    arg = strip(strip(arg, "-"), "/");
}


std::string reportLastError()
{
    DWORD error = GetLastError();
    return std::system_category().message(error);
}

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
 *  Paths are padded after the drive separator but before any path
 *  characters, i.e. C:[\\\\\\\]\path\to\exe with the section in []
 *  being the padded component
 * 
 * \param pth a pointer to the path to be padded
 * \param str_size the length of the path - not including any
 *                  null terminators.
 * \param bsize the lengh of the padding to add
 */
char * pad_path(const char *pth, DWORD str_size, DWORD bsize)
{
    size_t extended_buf = bsize - str_size + 2;
    char * padded_path = new char[bsize+1];
    for(int i = 0, j = 0; i < bsize && j < str_size; ++i){
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
    padded_path[bsize] = '\0';
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
    while(p != name.end() && *p == '\\') {
        ++c;
        ++p;
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
    char * chr_abs_out = new char [abs_out.length() + 1];
    strcpy(chr_abs_out, abs_out.c_str());
    replace_path_characters(chr_abs_out, abs_out.length());
    char * padded_path = pad_path(chr_abs_out, abs_out.length());
    mangled_abs_out = std::string(padded_path, MAX_NAME_LEN);

    delete chr_abs_out;
    delete padded_path;
    return mangled_abs_out;
}

/**
 * Determines whether a string contains path characters
 *  \param name string to check for path characters
 */
bool hasPathCharacters(const std::string &name) {
    typedef std::map<char, char>::const_iterator PathCharMap;
    for(PathCharMap it = path_to_special_characters.begin();
                it != path_to_special_characters.end(); ++it){
        if(!(name.find(it->first) == std::string::npos)){
            return true;
        }
    }
    return false;
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
    if (!res.empty()){
        return res;        
    }
    this->EvalSearchPaths();
    if (this->evald_search_paths.empty()) {
        return std::string();
    }
    // next search env variable paths
    for (std::string var: this->search_vars) {
        std::vector<std::string> searchable_paths = this->evald_search_paths.at(var);
        for (std::string pth: searchable_paths) {
            auto res = this->Finder(pth, lib_name);
            if (!res.empty()){
                return res;
            }
        }
    }
    return std::string();
}

void LibraryFinder::EvalSearchPaths() {
    if (!this->evald_search_paths.empty())
        return;
    for (std::string var: this->search_vars) {
        std::string envVal = GetSpackEnv(var.c_str());
        if (!envVal.empty()) {
            this->evald_search_paths[var] = split(envVal, ";");
        }
            
    }
}

/**
 * Searches files located at pth for a file called lib_name
 * \param pth the path at which to search for a given file
 * \param lib_name the file to be seached for
 * 
 * \return an empty string if nothing is found, the absolute path to
 * the discovered file with name lib_name
 */
std::string LibraryFinder::Finder(const std::string &pth, const std::string &lib_name) {
    WIN32_FIND_DATAW findFileData;
    // Globs all files at the provided path and matches to search
    // for lib name
    std::string searcher = pth + "\\*";
    HANDLE hFind = FindFirstFileW(ConvertAnsiToWide(searcher).c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::cerr << "Find file failed: " << reportLastError() << " " << searcher << "\n";
        FindClose(hFind);
        return std::string();
    }
    
    do {
        if (!wcscmp(findFileData.cFileName, ConvertAnsiToWide(lib_name).c_str())){
            return pth + "\\" + ConvertWideToANSI(findFileData.cFileName);
        }
    } while (FindNextFileW(hFind, &findFileData));

    DWORD dwError = GetLastError();
    if (dwError != ERROR_NO_MORE_FILES) {
        std::cerr << "Find file failed: "<< reportLastError() << "\n";
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

int get_slash_name_length(char *slash_name)
{
    if(slash_name == nullptr) {
        return 0;
    }
    int len = 0;
    // Maximum length for a given name in the PE/COFF format is 143 chars
    while(slash_name[len] != '/' && len < 144) {
        ++len;
    }
    return len;
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
