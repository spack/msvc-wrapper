#include "commandline.h"


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
        std::cerr << "Warning! Argument (" << val << ") not present\n";
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
        else if (endswith((std::string)args[i], ".lib")) {
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
        else if (!strcmp(args[i], "--debug") || !strcmp(args[i], "-d")) {
            opts.insert(std::pair<std::string, std::string>("debug", "on"));
        }
        else if (!strcmp(args[i], "--verify")) {
            opts.insert(std::pair<std::string, std::string>("verify", "on"));
        }
        else {
            // Unknown argument, warn the user it will not be used
            std::cerr << "Unknown argument: " << args[i] << " will be ignored\n";
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
    std::cout << "          --debug|-d                                    = Debug relocate run\n";
    std::cout << "          --verify                                      = Validates that a file is an import library\n";
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

