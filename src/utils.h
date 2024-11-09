#include <string>
#include <vector>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

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
std::string getSpackEnv(std::string env);
StrList getenvlist(std::string envVar, std::string delim = ";");
void validate_spack_env();

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
bool isPatch(const char * arg);

std::map<std::string, std::string> parsePatch(const char ** args, int argc);

bool checkAndPrintHelp(const char * arg);
