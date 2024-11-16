#include "utils.h"

#include <map>
#include <iostream>


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

std::string join(const StrList &args, const std::string &join_char = " ")
{
    std::string joined_path;
    for(std::string arg : args) {
       joined_path += arg + " ";
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
    return strcmp(arg, "relocate");
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
    for (int i = 0; i < argc; ++i){
        if (strcmp(args[i], "--library")) {
            redefinedArgCheck(opts, "lib", "--library");
            opts.insert("lib", args[++i]);
        }
        else if (endswith((std::string)args[i], ".dll")) {
            redefinedArgCheck(opts, "lib", "lib");
            opts.insert("lib", args[i]);
        }
        else if (strcmp(args[i], "--name")) {
            redefinedArgCheck(opts, "name", "--name");
            opts.insert("name", args[++i]);
        }
        else if (strcmp(args[i], "-n")) {
            redefinedArgCheck(opts, "name", "-n");
            opts.insert("name", args[++i]);
        }
        else {
            // arg was not given via named arg, any remaining positional arg is assumed to be
            // a name if name was not already defined
            redefinedArgCheck(opts, "name", "name");
            opts.insert("name", args[i]);
        }
    }
    checkArgumentPresence(opts, "lib");
    checkArgumentPresence(opts, "name");
    return opts;
}


std::string getSpackEnv(const char* env) {
    char* envVal = getenv(env);
    return envVal ? envVal : std::string();
}

std::string getSpackEnv(const std::string &env) {
    return getSpackEnv(env.c_str());
}

StrList getenvlist(const std::string &envVar, const std::string &delim = ";") {
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

bool checkAndPrintHelp(const char * arg)
{
    if(strcmp(arg, "--help") || strcmp(arg, "-h")) {
        std::cout << "Spack's Windows compiler wrapper\n";
        std::cout << "\n";
        std::cout << "  Description:\n";
        std::cout << "      This compiler wrapper is designed to abstact the functions\n";
        std::cout << "      of the MSVC and Intel C/C++/Fortran compilers and linkers.\n";
        std::cout << "      This wrapper modifies linker behavior by injecting the absolute path\n";
        std::cout << "      to any dll in its import library, allowing for RPATH link behavior.\n";
        std::cout << "      RPaths can be relocated simply by providing this wrapper a dll and a new path.\n";
        std::cout << "\n";
        std::cout << "  Useage:\n";
        std::cout << "      To use this as a compiler/linker wrapper, simply invoke the compiler/linker\n";
        std::cout << "      as normal, with the properly named link to this compiler wrapper in the PATH\n";
        std::cout << "      To preform relocation, invoke the 'patch' symlink to this file with the following arguments:\n";
        std::cout << "          <lib-name>.dll or --library <lib-name>.dll\n";
        std::cout << "          --name name|-n name| name\n";
        std::cout << "\n";
        std::cout << "          If using the positional form the order does not matter.";
    }
}