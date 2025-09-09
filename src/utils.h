/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>
#include <cctype>
#include <iostream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "version.h"

#define _STRING(m) #m
#define STRING(m) _STRING(m)

#define MAX_NAME_LEN 143

#define MIN_PADDING_THRESHOLD 8

enum ExitConditions {
    SUCCESS = 0,
    CLI_FAILURE,
    REPORT_FAILURE,
    RENAME_FAILURE,
    INVALID_ENVIRONMENT,
    INVALID_TOOLCHAIN,
    TOOLCHAIN_FAILURE,
    LIB_REMOVE_FAILURE,
    NORMALIZE_NAME_FAILURE,
    COFF_PARSE_FAILURE,
    FILE_RENAME_FAILURE
};

typedef std::vector<std::string> StrList;

// Environment Helper Methods
std::string GetSpackEnv(const char* env);
std::string GetSpackEnv(const std::string& env);
StrList GetEnvList(const std::string& envVar, const std::string& delim = ";");
bool ValidateSpackEnv();

// String helper methods adding cxx20 features to cxx14 //

// Returns true if arg starts with match
bool startswith(const std::string& arg, std::string& match);

// Returns true if arg starts with match
bool startswith(const std::string& arg, const char* match);

// Returns true of arg ends with match
bool endswith(const std::string& arg, std::string& match);

// Returns true of arg ends with match
bool endswith(const std::string& arg, char const* match);

// Converts W-char (std::wstring) string to ASCII (std::string) string
std::string ConvertWideToASCII(const std::wstring& wstr);

// Converts ASCII (std::string) to wide string (std::wstring)
std::wstring ConvertASCIIToWide(const std::string& str);

// Splits argument "s" by delineator delim
// Returns vector of strings, if delim is present
// Returns a single item list
StrList split(const std::string& s, const std::string& delim);

//Strips substr off the RHS of the larger string
std::string strip(const std::string& s, const std::string& substr);

//Strips substr of LHS of the larger string
std::string lstrip(const std::string& s, const std::string& substr);

// Joins vector of strings by join character
std::string join(const StrList& args, const std::string& join_char = " ");

// Returns filename stem
std::string stem(const std::string& file);

// Returns file basename
std::string basename(const std::string& file);

// Strips parent paths from path
void StripPath(std::string& command);

// Strips .exe extension from path
void StripExe(std::string& command);

// Drives both StripPath and StripExe on the same path
// resulting in a parentless, non exe extensioned path
void StripPathAndExe(std::string& command);

// Make str lowercase
void lower(std::string& str);

// Given a string containing something terminated by a
// forward slash, get the length of the substr terminated
// by /
int get_slash_name_length(const char* slash_name);

// Implementation of strstr but serch is bounded at size and
// does not terminate on the first read nullptr
char* findstr(char* search_str, const char* substr, size_t size);

// Adds quote to relevent strings in a list of strings
// Strings to be quoted contain: spaces, or any of &<>|()
// These are all legal path characters than have additional
// side effects on Windows
void quoteList(StrList& args);

/// @brief Searches a sections of a string for a given regex using provided
///     options to control search behavior
/// @param searchDomain - string to be searched
/// @param regex - regex used to search
/// @param opts - optional argument, list of regex tuning options to adapt the search behavior
/// @return Character sequence matching search regex
std::string regexSearch(
    const std::string& searchDomain, const std::string& regex,
    const std::vector<std::regex_constants::syntax_option_type>& opts = {},
    const std::vector<std::regex_constants::match_flag_type>& flags = {});

/// @brief Tries to match an entire string to a given regex using provided
///     options to control match behavior
/// @param searchDomain - string to be matched
/// @param regex - regex used to match
/// @param opts - optional argument, list of regex tuning options to adapt the match behavior
/// @return Character sequence matching regex
std::string regexMatch(
    const std::string& searchDomain, const std::string& regex,
    const std::vector<std::regex_constants::syntax_option_type>& opts = {},
    const std::vector<std::regex_constants::match_flag_type>& flags = {});

/// @brief Searches a string for a given regex using provided
///     options to control search behavior, and if found, replaces
///     discovered string with given replacement string
/// @param searchDomain - string to be searched
/// @param regex - regex used to search
/// @param replacement - string used to replace regex matched result
/// @param opts - optional argument, list of regex tuning options to adapt the search behavior
/// @return Character sequence matching search regex
std::string regexReplace(
    const std::string& replaceDomain, const std::string& regex,
    const std::string& replacement,
    const std::vector<std::regex_constants::syntax_option_type>& opts = {},
    const std::vector<std::regex_constants::match_flag_type>& flags = {});

// FS/Path helpers //

// Returns current working directory
std::string GetCWD();

// Returns boolean indication whether pth is absolute
bool IsPathAbsolute(const std::string& pth);

bool hasPathCharacters(const std::string& name);

std::string mangle_name(const std::string& name);

int get_padding_length(const std::string& name);

char* pad_path(const char* pth, DWORD str_size, DWORD bsize = MAX_NAME_LEN);

void replace_path_characters(char* path, size_t len);

void replace_special_characters(char* mangled, size_t len);

bool SpackInstalledLib(const std::string& lib);

// File and File handle helpers //

// Returns File offset given RVA
DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER& section_header,
                      DWORD number_of_sections, DWORD rva);

// Error checked handle cleanup to ensure all file handles are appropriately closed
// while avoiding closing an already closed or in use handle
int SafeHandleCleanup(HANDLE& handle);

// System Helpers //
std::string reportLastError();

// Data helpers //

// Converts big endian data to little endian form
// Windows is little endian, but stores some values in PE
// files in big endian format
DWORD ToLittleEndian(DWORD val);

// Operating Utils //

void debug(const std::string& dbgStmt);

void debug(char* dbgStmt, int len);

bool isCommandArg(const std::string& arg, const std::string& command);

void normalArg(std::string& arg);

/**
 * Library Searching utility class
 *  Collection of heuristics and logic surrounding library
 *  searching on a filesystem
 * 
 *  Takes a library to search for and collects information about the search
 *  including any libraries found with that name, the variables used to search
 *  and the paths evaluated for that library location
 * 
 *  Differentiates between system and user libraries
 */
class LibraryFinder {
   private:
    std::map<std::string, std::string> found_libs;
    std::vector<std::string> search_vars;
    std::map<std::string, std::vector<std::string>> evald_search_paths;
    static std::string Finder(const std::string& pth,
                              const std::string& lib_name);
    static bool IsSystem(const std::string& pth);

   public:
    LibraryFinder();
    std::string FindLibrary(const std::string& lib_name,
                            const std::string& lib_path);
    void EvalSearchPaths();
};

const std::map<char, char> special_character_to_path{{'|', '\\'}, {';', ':'}};

const std::map<char, char> path_to_special_characters{{'\\', '|'},
                                                      {'/', '|'},
                                                      {':', ';'}};

class SpackCompilerWrapperError : public std::runtime_error {
   public:
    SpackCompilerWrapperError(char const* const message);
    virtual char const* what() const;
};

static bool DEBUG = false;
