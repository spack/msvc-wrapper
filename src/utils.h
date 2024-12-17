#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <map>

#include "version.h"

#define _STRING(m) #m
#define STRING(m) _STRING(m)

typedef std::vector<std::string> StrList;

class SpackException : public std::exception {
public:
    SpackException(std::string msg) : message(msg) {}
    char const* what();
protected:
    std::string message;
};

class SpackUnknownCompilerException : public SpackException {
    using SpackException::SpackException;
public:
    char const * what();
};

class SpackCompilerException : public SpackException {
    using SpackException::SpackException;
public:
    char const * what();
};

class SpackCompilerContextException : public SpackException {
    using SpackException::SpackException;
public:
    char const * what();
};


// Environment Helper Methods
std::string getSpackEnv(const char* env);
std::string getSpackEnv(const std::string &env);
StrList getenvlist(const std::string &envVar, const std::string &delim = ";");
void validate_spack_env();

// String helper methods adding cxx20 features to cxx14

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

// Determines if a command line invocation is for the relocate form
// of this executable
bool isRelocate(const char * arg);

// Parses the command line for an invocation of the relocate command
// and returns the arguments mapped from argument name to value
std::map<std::string, std::string> parseRelocate(const char ** args, int argc);

// Writes CLI help message to stdout
bool checkAndPrintHelp(const char ** arg, int argc);

// Returns filename stem
std::string stem(const std::string &file);

// Returns file basename
std::string basename(const std::string &file);

// Returns current working directory
std::string getCWD();

// Returns boolean indication whether pth is absolute
bool isPathAbsolute(const std::string &pth);

// Returns File offset given RVA
DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER section_header, DWORD number_of_sections, DWORD rva);

class LibraryFinder {
private:
    std::map<std::string, std::string> found_libs;
    std::vector<std::string> search_vars;
    std::map<std::string, std::vector<std::string>> evald_search_paths;
    std::string finder(const std::string &pth, const std::string &lib_name);
    bool is_system(const std::string &pth);
public:
    LibraryFinder();
    std::string find_library(const std::string &lib_name);
    void eval_search_paths();
};
