/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <sstream>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <cctype> 

#include "version.h"

#define _STRING(m) #m
#define STRING(m) _STRING(m)

#define MAX_NAME_LEN 143

typedef std::vector<std::string> StrList;

// Environment Helper Methods
std::string GetSpackEnv(const char* env);
std::string GetSpackEnv(const std::string &env);
StrList GetEnvList(const std::string &envVar, const std::string &delim = ";");
int ValidateSpackEnv();

// String helper methods adding cxx20 features to cxx14 //

// Returns true if arg starts with match
bool startswith(const std::string &arg, std::string &match);

// Returns true if arg starts with match
bool startswith(const std::string &arg, const char * match);

// Returns true of arg ends with match
bool endswith(const std::string &arg, std::string &match);

// Returns true of arg ends with match
bool endswith(const std::string &arg, char const* match);

// Converts W-char (std::wstring) string to ansi (std::string) string
std::string ConvertWideToANSI(const std::wstring &wstr);

// Converts ANSI (std::string) to wide string (std::wstring)
std::wstring ConvertAnsiToWide(const std::string &str);

// Splits argument "s" by delineator delim
// Returns vector of strings, if delim is present
// Returns a single item list
StrList split(const std::string &s, const std::string &delim);

//Strips substr off the RHS of the larger string
std::string strip(const std::string& s, const std::string &substr);

// Joins vector of strings by join character
std::string join(const StrList &strs, const std::string &join_char = " ");

// Returns filename stem
std::string stem(const std::string &file);

// Returns file basename
std::string basename(const std::string &file);

// Strips parent paths from path
void StripPath(std::string &command);

// Strips .exe extension from path
void StripExe(std::string &command);

// Drives both StripPath and StripExe on the same path
// resulting in a parentless, non exe extensioned path
void StripPathAndExe(std::string &command);

// Implementation of strstr but serch is bounded at size and
// does not terminate on the first read nullptr
char * findstr(char * search_str, const char * substr, int size);

// CLI HELPERS //

// Determines if a command line invocation is for the relocate form
// of this executable
bool IsRelocate(const char * arg);

// Determines if a command line invocation is for the report form of this
// Executable
bool IsReport(const char * arg);

// Parses the command line for an invocation of the relocate command
// and returns the arguments mapped from argument name to value
std::map<std::string, std::string> ParseRelocate(const char ** args, int argc);

// Parses the command line for an invocation of the report command
// adn returns the arguments mappedfrom argument name to value
std::map<std::string, std::string> ParseReport(int argc, const char ** args);

// Writes CLI help message to stdout
bool CheckAndPrintHelp(const char ** arg, int argc);

// FS/Path helpers //

// Returns current working directory
std::string GetCWD();

// Returns boolean indication whether pth is absolute
bool IsPathAbsolute(const std::string &pth);

// File and File handle helpers //

// Returns File offset given RVA
DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER &section_header, DWORD number_of_sections, DWORD rva);

// Error checked handle cleanup to ensure all file handles are appropriately closed
// while avoiding closing an already closed or in use handle
int SafeHandleCleanup(HANDLE &handle);

// Data helpers //

// Converts big endian data to little endian form
// Windows is little endian, but stores some values in PE
// files in big endian format
DWORD ToLittleEndian(DWORD val);

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
    std::string Finder(const std::string &pth, const std::string &lib_name);
    bool IsSystem(const std::string &pth);
public:
    LibraryFinder();
    std::string FindLibrary(const std::string &lib_name);
    void EvalSearchPaths();
};
