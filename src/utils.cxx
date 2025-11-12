/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "utils.h"
#include <errhandlingapi.h>
#include <fileapi.h>
#include <fstream>
#include <handleapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <processenv.h>
#include <stringapiset.h>
#include <winbase.h>
#include <winerror.h>
#include <winnls.h>
#include <winnt.h>
#include <winsock.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <exception>
#include <iostream>
#include <limits>
#include <map>
#include <regex>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>
#include "shlwapi.h"

//////////////////////////////////////////////////////////
// String helper methods adding cxx20 features to cxx14 //
//////////////////////////////////////////////////////////

bool checkSizeTConversion(const std::string& str) {
    constexpr int KMaxInt = (std::numeric_limits<int>::max)();
    return str.length() > static_cast<size_t>(KMaxInt);
}

bool checkSizeTConversion(const std::wstring& wstr) {
    constexpr int KMaxInt = (std::numeric_limits<int>::max)();
    return wstr.length() > static_cast<size_t>(KMaxInt);
}

/**
 * Returns true of arg starts with match
 */
bool startswith(const std::string& arg, const std::string& match) {
    size_t const match_len = match.size();
    if (match_len > arg.size())
        return false;
    return arg.compare(0, match_len, match) == 0;
}

/**
 * Returns true if arg starts with match
 */
bool startswith(const std::string& arg, const char* match) {
    return startswith(arg, std::string(match));
}

/**
 * Returns true if arg ends with match
 */
bool endswith(const std::string& arg, const std::string& match) {
    size_t const match_len = match.size();
    if (match_len > arg.size())
        return false;
    return arg.compare(arg.size() - match_len, match_len, match) == 0;
}

/**
 * Returns true if arg ends with match
 */
bool endswith(const std::string& arg, char const* match) {
    return endswith(arg, std::string(match));
}

/**
 * Converts wide strings to ASCII (standard) strings
 * 
 * Converts wstring to string
 */
std::string ConvertWideToASCII(const std::wstring& wstr) {
    bool const string_too_long = checkSizeTConversion(wstr);
    if (string_too_long) {
        throw std::overflow_error(
            "Input string is too long: size_t-length doesn't fit into int.");
    }

    int const count = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(),
                                          static_cast<int>(wstr.length()),
                                          nullptr, 0, nullptr, nullptr);
    std::string str(count, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], count, nullptr,
                        nullptr);
    return str;
}

/**
 * Converts standard strings to wide strings
 * 
 * Converts string to wstring
 */
std::wstring ConvertASCIIToWide(const std::string& str) {
    bool const str_too_long = checkSizeTConversion(str);
    if (str_too_long) {
        throw std::overflow_error(
            "Input string is too long: size_t-length doesn't fit into int.");
    }
    int const count = MultiByteToWideChar(
        CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0);
    std::wstring wstr(count, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()),
                        &wstr[0], count);
    return wstr;
}

/**
 * Decomposes the input string into a list separated by
 * delim
 * 
 * Count determines how many delims will be processed
 * if count > 0
 * if count == 0, all delimiters are split
 * 
 * Returns the list produced by breaking up input string s on delim
 */
StrList split(const std::string& str, const std::string& delim,
              const u_int count) {
    size_t pos_start = 0;
    size_t pos_end;
    size_t const delim_len = delim.length();
    std::string token;
    StrList res = StrList();
    bool delim_count_reached = false;
    u_int delim_count = 0;
    while (((pos_end = str.find(delim, pos_start)) != std::string::npos) &&
           !delim_count_reached) {
        size_t const token_len = pos_end - pos_start;
        token = str.substr(pos_start, token_len);
        pos_start = pos_end + delim_len;
        if (token == delim || token.empty()) {
            continue;
        }
        res.push_back(token);
        ++delim_count;
        if (count) {
            delim_count_reached = count == delim_count;
        }
    }
    res.push_back(str.substr(pos_start));
    return res;
}

/**
 * Strips substring from the end of input string s
 * 
 * Returns stripped version of s
 */
std::string strip(const std::string& str, const std::string& substr) {
    if (!endswith(str, substr))
        return str;
    return str.substr(0, str.size() - substr.size());
}

/**
 * Strips substring from the beginning of input string s
 * 
 * Returns stripped version of s
 */
std::string lstrip(const std::string& str, const std::string& substr) {
    if (!startswith(str, substr))
        return str;
    return str.substr(substr.size(), str.size());
}

/**
 * combines list of strings into one string joined on join_char
 */
std::string join(const StrList& args, const std::string& join_char) {
    std::string joined_path;
    for (const std::string& arg : args) {
        joined_path += arg + join_char;
    }
    // Remove trailing token
    const size_t last_token_pos = joined_path.rfind(join_char);
    if (last_token_pos != std::string::npos) {
        joined_path.erase(last_token_pos, joined_path.length());
    }
    return joined_path;
}

/**
 * @brief Removes trailing extenion from a path
 * i.e. from /path/to/my/file.txt.tmp this method
 * would remove .tmp and return 
 * /path/to/my/file.txt
 * @param path - path to have trailing ext removed from 
 * 
 * @return path with last ext removed
 */
std::string stripLastExt(const std::string& path) {
    // ensure we're only operating on file component
    const std::string base = basename(path);
    const size_t ext_pos = base.rfind('.');
    std::string path_no_ext;
    if (ext_pos != std::string::npos) {
        const size_t ext_len = base.length() - ext_pos;
        path_no_ext = path.substr(0, path.length() - ext_len);
    }
    return path_no_ext;
}

void StripPathAndExe(std::string& command) {
    StripPath(command);
    StripExe(command);
};

void StripExe(std::string& command) {
    // Normalize command to lowercase to avoid parsing issues
    lower(command);
    std::string::size_type const loc = command.rfind(".exe");
    if (std::string::npos != loc && loc + 4 == command.length())
        command.erase(loc);
}

void StripPath(std::string& command) {
    command.erase(0, command.find_last_of("\\/") + 1);
}

/**
 * Converts a string to lowercase
 * 
 * \arg str - string to be made lowercase
 */
void lower(std::string& str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char item) {
        return static_cast<char>(std::tolower(item));
    });
}

/**
 * Quotes str as needed
 *  If str has existing escaped quotes, or a space/reserved character
 *  Escape escaped quotes using an escaped backslash preceding the escaped
 *  quote. Escape reserved characters by quoting the entire string
 * 
 *  Return the escaped string
 */
std::string quoteAsNeeded(std::string& str) {
    // Note: the ordering if these two conditionals is important
    // If the second conditional is executed first, the first
    // will always be true as the second injects the string
    // on which the first is conditioned
    // Basically: If we find escaped strings: escape em again
    // If we find space/special chars: escape the whole string

    if (str.find_first_of('\"') != std::string::npos) {
        // If there are escaped quotes in input
        // We need to escape them as well as we're adding another
        // layer of indirection between caller and compiler
        std::regex const pattern("\"");
        str = std::regex_replace(str, pattern, "\\\"");
    }
    if (str.find_first_of(" &<>|()") != std::string::npos) {
        // There are spaces or special characters in string, quote it
        str = "\"" + str + "\"";
    }
    return str;
}

void quoteList(StrList& args) {
    std::transform(args.begin(), args.end(), args.begin(), quoteAsNeeded);
}

std::regex_constants::syntax_option_type composeRegexOptions(
    const std::vector<std::regex_constants::syntax_option_type>& opts) {
    std::regex_constants::syntax_option_type composed_opt;
    if (opts.empty()) {
        // Default option
        composed_opt = std::regex_constants::syntax_option_type::ECMAScript;
    }
    for (std::regex_constants::syntax_option_type const opt : opts) {
        composed_opt |= opt;
    }
    return composed_opt;
}

std::regex_constants::match_flag_type composeMatchTypes(
    const std::vector<std::regex_constants::match_flag_type>& flags) {
    std::regex_constants::match_flag_type composed_flag;
    if (flags.empty()) {
        // Default option
        composed_flag = std::regex_constants::match_flag_type::match_default;
    }
    for (std::regex_constants::match_flag_type const flag : flags) {
        composed_flag |= flag;
    }
    return composed_flag;
}

std::string regexSearch(
    const std::string& searchDomain, const std::string& regex,
    const std::vector<std::regex_constants::syntax_option_type>& opts,
    const std::vector<std::regex_constants::match_flag_type>& flags) {
    std::string result_str;
    std::regex_constants::syntax_option_type const opt =
        composeRegexOptions(opts);
    std::regex_constants::match_flag_type const flag = composeMatchTypes(flags);
    std::regex const reg(regex, opt);
    std::smatch match;
    if (!std::regex_search(searchDomain, match, reg, flag)) {
        result_str = std::string();
    } else {
        result_str = match.str();
    }
    return result_str;
}

std::string regexMatch(
    const std::string& searchDomain, const std::string& regex,
    const std::vector<std::regex_constants::syntax_option_type>& opts,
    const std::vector<std::regex_constants::match_flag_type>& flags) {
    std::string result_str;
    std::regex_constants::syntax_option_type const opt =
        composeRegexOptions(opts);
    std::regex_constants::match_flag_type const flag = composeMatchTypes(flags);
    std::regex const reg(regex, opt);
    std::smatch match;
    if (!std::regex_match(searchDomain, match, reg, flag)) {
        result_str = std::string();
    } else {
        result_str = match.str();
    }
    return result_str;
}

std::string regexReplace(
    const std::string& replaceDomain, const std::string& regex,
    const std::string& replacement,
    const std::vector<std::regex_constants::syntax_option_type>& opts,
    const std::vector<std::regex_constants::match_flag_type>& flags) {
    std::regex_constants::syntax_option_type const opt =
        composeRegexOptions(opts);
    std::regex_constants::match_flag_type const flag = composeMatchTypes(flags);
    std::regex const reg(regex, opt);
    return std::regex_replace(replaceDomain, reg, replacement, flag);
}

/**
 * Given an environment variable name
 * return the corresponding environment variable value
 * or an empty string as appropriate
 */
std::string GetSpackEnv(const char* env) {
    char const* env_val = getenv(env);
    return env_val ? env_val : std::string();
}

/**
 * Given an environment variable name
 * return the corresponding environment variable value
 * or an empty string as appropriate
 */
std::string GetSpackEnv(const std::string& env) {
    return GetSpackEnv(env.c_str());
}

/**
 * Returns list of strings from environment variable value
 * representing a list delineated by delim argument
 */
StrList GetEnvList(const std::string& envVar, const std::string& delim) {
    std::string const env_value = GetSpackEnv(envVar);
    if (!env_value.empty())
        return split(env_value, delim);

    return StrList();
}

bool ValidateSpackEnv() {
    std::vector<std::string> const spack_env{
        "SPACK_COMPILER_WRAPPER_PATH", "SPACK_DEBUG_LOG_DIR",
        "SPACK_DEBUG_LOG_ID",          "SPACK_SHORT_SPEC",
        "SPACK_SYSTEM_DIRS",           "SPACK_MANAGED_DIRS"};
    for (const auto& var : spack_env)
        if (!getenv(var.c_str())) {
            std::cerr
                << var +
                       " isn't set in the environment and is expected to be\n";
            return false;
        }
    return true;
}

std::string stem(const std::string& file) {
    std::size_t const last_dot = file.find_last_of('.');
    if (last_dot == std::string::npos) {
        return file;
    }
    return file.substr(0, last_dot);
}

std::string basename(const std::string& file) {
    size_t const last_path = file.find_last_of('\\') + 1;
    if (last_path == std::string::npos) {
        return file;
    }
    return file.substr(last_path);
}

std::string GetCWD() {
    DWORD buf_size;
    buf_size = GetCurrentDirectoryW(0, nullptr);
    auto* w_cwd = new wchar_t[buf_size];
    GetCurrentDirectoryW(buf_size, w_cwd);
    std::wstring const ws_cwd(w_cwd);
    free(w_cwd);
    try {
        std::string s_cwd = ConvertWideToASCII(ws_cwd);
        return s_cwd;
    } catch (const std::overflow_error& e) {
        std::cerr << e.what() << "\n";
        return std::string();
    }
}

bool IsPathAbsolute(const std::string& pth) {
    return PathIsRelativeA(pth.c_str()) == 0;
}

/**
 * Determines the file offset on disk from the relative virtual address of a given section
 * header
 */
DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER& section_header,
                      DWORD number_of_sections, DWORD rva) {

    for (DWORD i = 0; i < number_of_sections; ++i, ++section_header) {
        DWORD const section_start_rva = section_header->VirtualAddress;
        DWORD const section_end_rva =
            section_start_rva + section_header->SizeOfRawData;
        // check section bounds for RVA
        if (rva >= section_start_rva && rva < section_end_rva) {
            DWORD const file_offset =
                rva - section_start_rva + section_header->PointerToRawData;
            return file_offset;
        }
    }
    std::cerr << "Error: RVA 0x" << std::hex << rva
              << " not found in any section." << '\n';
    return 0;
}

void debug(const std::string& dbgStmt) {
    if (DEBUG || getenv("SPACK_DEBUG_WRAPPER")) {
        std::cout << "DEBUG: " << dbgStmt << "\n";
    }
}

void debug(char* dbgStmt, int len) {
    debug(std::string(dbgStmt, len));
}

bool isCommandArg(const std::string& arg, const std::string& command) {
    const std::string slash_opt = "/" + command;
    const std::string dash_opt = "-" + command;
    return startswith(arg, slash_opt) || startswith(arg, dash_opt);
}

void normalArg(std::string& arg) {
    // first normalize capitalization
    lower(arg);
    // strip any leading/trailing quotes
    arg = strip(lstrip(arg, "\""), "\"");
    // strip leading / and -
    arg = lstrip(lstrip(arg, "-"), "/");
}

std::string reportLastError() {
    DWORD const error = GetLastError();
    return std::system_category().message(
        error);  // NOLINT(bugprone-narrowing-conversions)
}

/**
 * Replaces characters used to mangle path characters with
 * valid path characters
 * 
 * \param in a pointer to the string to replace the mangled path characters in
 * \param len the length of the mangled path
 */
void replace_special_characters(char* mangled, size_t len) {
    for (int i = 0; i < len; ++i) {
        if (special_character_to_path.count(mangled[i])) {
            mangled[i] = special_character_to_path.at(mangled[i]);
        }
    }
}

/**
 * Replaces path characters with special, non path, replacement characters
 * 
 * \param in a pointer to the string to have its path characters replace with special placeholders
 * \param len the length of the path to be mangled
 */
void replace_path_characters(char* path, size_t len) {
    for (int i = 0; i < len; i++) {
        if (path_to_special_characters.count(path[i]))
            path[i] = path_to_special_characters.at(path[i]);
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
char* pad_path(const char* pth, DWORD str_size, DWORD bsize) {
    // If str_size > bsize we get inappropriate conversion
    // from signed to unsigned
    if (str_size > bsize) {
        debug("Padding string is greater than max string size allowed");
        return nullptr;
    }
    size_t const extended_buf = bsize - str_size + 2;
    char* padded_path = new char[bsize + 1];
    for (DWORD i = 0, j = 0; i < bsize && j < str_size; ++i) {
        if (i < 2 || i >= extended_buf) {
            padded_path[i] = pth[j];
            ++j;
        } else {
            padded_path[i] = '|';
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
int get_padding_length(const std::string& name) {
    int count = 0;
    std::string::const_iterator padding = name.cbegin();
    padding += 2;
    while (padding != name.end() && *padding == '\\') {
        ++count;
        ++padding;
    }
    return count;
}

std::string strip_padding(const std::string& lib) {
    // One of the padding characters is a legitimate
    // path separator
    int const pad_len = get_padding_length(lib) - 1;
    // Capture the drive and drive separator
    std::string::const_iterator const p = lib.cbegin();
    std::string::const_iterator e = lib.cbegin() + 2;
    std::string const stripped_drive(p, e);
    e = e + pad_len;
    std::string const path_remainder(e, lib.end());
    return stripped_drive + path_remainder;
}

/**
 * Compute and return the SFN of a given path
 *   utilizes the string parsing escape prefix
 *   to allow processing paths that are longer
 *   than the system MAX_PATH_LENGTH
 *   (different from MAX_NAME_LEN)
 */
std::string getSFN(const std::string& path) {
    // Use "disable string parsing" prefix in case
    // the path is too long
    std::string const escaped = R"(\\?\)" + path;
    // Get SFN length so we can create buffer
    DWORD const sfn_size =
        GetShortPathNameA(escaped.c_str(), NULL, 0);  //NOLINT
    char* sfn = new char[sfn_size + 1];
    GetShortPathNameA(escaped.c_str(), sfn, escaped.length());
    // sfn is null terminated per win32 api
    // Ensure we strip out the disable string parsing prefix
    std::string s_sfn = lstrip(sfn, R"(\\?\)");
    delete[] sfn;
    return s_sfn;
}

/**
 * Replace path with the SFN representation
 *   will raise an exception NameTooLongError if
 *   post SFN conversion, the path is still longer
 *   than the MAX_NAME_LEN limit
 */
std::string short_name(const std::string& path) {
    // Get SFN for path to name
    std::string const new_abs_out = getSFN(path);
    if (new_abs_out.length() > MAX_NAME_LEN) {
        std::cerr << "DLL path " << path << " too long to relocate.\n";
        std::cerr << "Shortened DLL path " << new_abs_out
                  << " also too long to relocate.\n";
        std::cerr << "Please move Spack prefix "
                  << " to a shorter directory.\n";
        throw NameTooLongError("DLL Path too long, cannot be relocated.");
    }
    return new_abs_out;
}

/**
 * Mangles a string representing a path to have no path characters
 *  instead path characters (i.e. \\, :, etc) are replaced with
 *  special replacement characters
 * 
 * \param name the string to be mangled
 */
std::string mangle_name(const std::string& name) {
    std::string abs_out;
    std::string mangled_abs_out;
    if (IsPathAbsolute(name)) {
        abs_out = name;
    } else {
        // relative paths, assume they're relative to the CWD of the linker (as they have to be)
        abs_out = join({GetCWD(), name}, "\\");
    }
    // Now that we have the full path, check size
    if (abs_out.length() > MAX_NAME_LEN) {
        // Name is too long we need to attempt to shorten
        std::string const new_abs_out = short_name(abs_out);
        // If new, shortened path is too long, bail
        abs_out = new_abs_out;
    }
    char* chr_abs_out = new char[abs_out.length() + 1];
    strcpy(chr_abs_out, abs_out.c_str());
    replace_path_characters(chr_abs_out, abs_out.length());
    char const* padded_path =
        pad_path(chr_abs_out, static_cast<DWORD>(abs_out.length()));
    mangled_abs_out = std::string(padded_path, MAX_NAME_LEN);

    delete[] chr_abs_out;
    delete padded_path;
    return mangled_abs_out;
}

bool fileExists(const std::string& fname) {
    std::ifstream file(fname);
    bool const exists = file.good();
    file.close();
    return exists;
}

/**
 * Determines whether a string contains path characters
 *  \param name string to check for path characters
 */
bool hasPathCharacters(const std::string& name) {
    for (auto it = path_to_special_characters.begin();
         it != path_to_special_characters.end(); ++it) {
        if (!(name.find(it->first) == std::string::npos)) {
            return true;
        }
    }
    return false;
}

bool SpackInstalledLib(const std::string& lib) {
    const std::string prefix = GetSpackEnv("SPACK_INSTALL_PREFIX");
    if (prefix.empty()) {
        debug(
            "Unable to determine Spack install prefix, SPACK_INSTALL_PREFIX "
            "unset");
        return false;
    }
    std::string const stripped_lib = strip_padding(lib);
    startswith(stripped_lib, prefix);
}

LibraryFinder::LibraryFinder() : search_vars{"SPACK_RELOCATE_PATH"} {}

std::string LibraryFinder::FindLibrary(const std::string& lib_name,
                                       const std::string& lib_path) {
    // Read env variables and split into paths
    // Only ever run once
    // First check if lib is absolute path
    if (LibraryFinder::IsSystem(lib_path)) {
        return std::string();
    }
    // next search the CWD
    std::string const cwd(GetCWD());
    auto cwd_res = LibraryFinder::Finder(cwd, lib_name);
    if (!cwd_res.empty()) {
        return cwd_res;
    }
    this->EvalSearchPaths();
    if (this->evald_search_paths.empty()) {
        return std::string();
    }
    // next search env variable paths
    for (const std::string& var : this->search_vars) {
        std::vector<std::string> const searchable_paths =
            this->evald_search_paths.at(var);
        for (const std::string& pth : searchable_paths) {
            auto res = LibraryFinder::Finder(pth, lib_name);
            if (!res.empty()) {
                return res;
            }
        }
    }
    return std::string();
}

void LibraryFinder::EvalSearchPaths() {
    if (!this->evald_search_paths.empty())
        return;
    for (const std::string& var : this->search_vars) {
        std::string const env_val = GetSpackEnv(var.c_str());
        if (!env_val.empty()) {
            this->evald_search_paths[var] = split(env_val, ";");
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
std::string LibraryFinder::Finder(const std::string& pth,
                                  const std::string& lib_name) {
    WIN32_FIND_DATAW find_file_data;
    // Globs all files at the provided path and matches to search
    // for lib name
    std::string const searcher = pth + "\\*";
    std::wstring search_str;
    try {
        search_str = ConvertASCIIToWide(searcher);
    } catch (const std::overflow_error& e) {
        std::cerr << e.what() << "\n";
        return std::string();
    }
    HANDLE h_find = FindFirstFileW(search_str.c_str(), &find_file_data);
    if (h_find == INVALID_HANDLE_VALUE) {
        std::cerr << "Find file failed: " << reportLastError() << " "
                  << searcher << "\n";
        FindClose(h_find);
        return std::string();
    }

    do {
        try {
            if (wcscmp(find_file_data.cFileName,
                       ConvertASCIIToWide(lib_name).c_str()) == 0) {
                return pth + "\\" +
                       ConvertWideToASCII(find_file_data.cFileName);
            }
        } catch (const std::overflow_error& e) {
            debug("Overflow converting " + lib_name +
                  "to alternate representation\n" + "Exception: " + e.what());
        }
    } while (FindNextFileW(h_find, &find_file_data));

    DWORD const dw_error = GetLastError();
    if (dw_error != ERROR_NO_MORE_FILES) {
        std::cerr << "Find file failed: " << reportLastError() << "\n";
    }
    FindClose(h_find);
    return std::string();
}

namespace {
std::vector<std::string> system_locations = {
    "api-ms-", "ext-ms-",   "ieshims", "emclient", "devicelock",
    "wpax",    "vcruntime", "WINDOWS", "system32", "KERNEL32",
    "WS2_32",  "dbghelp",   "bcrypt",  "ADVAPI32", "SHELL32",
    "CRYPT32", "USER32",    "ole32",   "OLEAUTH32"};

}

bool LibraryFinder::IsSystem(const std::string& pth) {
    return std::any_of(system_locations.cbegin(), system_locations.cend(),
                       [&](const std::string& loc) {
                           return pth.find(loc) != std::string::npos;
                       });
}

int SafeHandleCleanup(HANDLE& handle) {
    if (handle != INVALID_HANDLE_VALUE) {
        if (!CloseHandle(handle)) {
            return 0;
        }
    }
    return 1;
}

DWORD ToLittleEndian(DWORD val) {
    DWORD const little_endian_val = (val >> 24) | ((val & 0x00FF0000) >> 8) |
                                    ((val & 0x0000FF00) << 8) | (val << 24);
    return little_endian_val;
}

int get_slash_name_length(const char* slash_name) {
    if (slash_name == nullptr) {
        return 0;
    }
    int len = 0;
    // Maximum length for a given name in the PE/COFF format is 143 chars
    while (slash_name[len] != '/' && len <= MAX_NAME_LEN) {
        ++len;
    }
    return len;
}

char* findstr(char* search_str, const char* substr, size_t size) {
    char* search = search_str;  // NOLINT
    size_t const str_size = strlen(substr);
    while (search < search_str + size) {
        if (!strncmp(search, substr, str_size)) {
            return search;
        }
        ++search;
    }
    return nullptr;
}

NameTooLongError::NameTooLongError(char const* const message)
    : std::runtime_error(message) {}

char const* NameTooLongError::what() const {
    return exception::what();
}