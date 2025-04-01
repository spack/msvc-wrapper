#include <map>
#include <iostream>
#include <string>
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