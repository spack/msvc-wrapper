#include <string>
#include <vector>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

typedef std::vector<std::string> StrList;
// String helper methods adding cxx20 features to cxx14

// Returns true if arg starts with match
bool startswith(std::string &arg, std::string &match);

// Returns true if arg starts with match
bool startswith(std::string &arg, const char * match);

// Returns true of arg ends with match
bool endswith(std::string &arg, std::string &match);

// Returns true of arg ends with match
bool endswith(std::string &arg, char const* match);

// Converts W-char (std::wstring) string to ansi (std::string) string
std::string ConvertWideToANSI(const std::wstring &wstr);

// Converts ANSI (std::string) to wide string (std::wstring)
std::wstring ConvertAnsiToWide(const std::string &str);

// Splits argument "s" by delineator delim
// Returns vector of strings, if delim is present
// Returns a single item list
StrList split(std::string s, std::string delim);

// Parse command line opts
bool isPatch(const char ** begin, const char ** end);

StrList parsePatch(const char ** args);
