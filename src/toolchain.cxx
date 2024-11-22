#include "toolchain.h"

#include <sstream>

ToolChainInvocation::ToolChainInvocation(std::string command, char const* const* cli)
{
    this->command = command;
    this->parse_command_args(cli);
}

void ToolChainInvocation::interpolateSpackEnv(SpackEnvState &spackenv) {
    // inject Spack includes before the default includes
    for( auto &include: spackenv.SpackIncludeDirs )
    {
        auto incArg = this->composeIncludeArg(include);
        this->includeArgs.insert(this->includeArgs.begin(), incArg);
    }
    for( auto &lib: spackenv.SpackLdLibs )
    {
        this->libArgs.push_back(lib);
    }
    this->addExtraLibPaths(spackenv.SpackLinkDirs);
    this->addExtraLibPaths(spackenv.SpackRPathDirs);
    this->addExtraLibPaths(spackenv.SpackCompilerExtraRPaths);
    this->addExtraLibPaths(spackenv.SpackCompilerImplicitRPaths);
    this->loadToolchainDependentSpackVars(spackenv);
}

void ToolChainInvocation::invokeToolchain() {
    StrList commandLine(this->composeCommandLists({
        this->commandArgs,
        this->includeArgs,
        this->libArgs,
        this->libDirArgs,
        this->objArgs
    }));

    this->executor = ExecuteCommand(  this->spackCommand,
                                      commandLine
                                    );
    // Run first pass of command as requested by caller
    this->executor.execute();
}

void ToolChainInvocation::parse_command_args(char const* const* cli) {
    // Collect include args as we need to ensure Spack
    // Includes come first
    for( char const* const* c = cli; *c; c++ ){
        std::string arg = std::string(*c);
        if ( startswith(arg, "/I") ) {
            // We have an include arg
            // can have an optional space
            // check if there are characters after
            // "/I" and if not we consider the next
            // argument to be the include
            if (arg.size() > 2)
                this->includeArgs.push_back(arg);
            else
                this->includeArgs.push_back(std::string(*(++c)));
        }
        else if( endswith(arg, ".lib") )
            // Lib args are just libraries
            // provided like system32.lib on the
            // command line.
            // lib specification order does not matter
            // on MSVC but this is useful for filtering system libs
            // and adding all libs
            this->libArgs.push_back(arg);
        else if ( endswith(arg, ".obj") )
            this->objArgs.push_back(arg);
        else
            this->commandArgs.push_back(arg);
    }
}

std::string ToolChainInvocation::composeIncludeArg(std::string &include) {
    return "/I" + include;
}

std::string ToolChainInvocation::composeLibPathArg(std::string &libPath) {
    return "/LIBPATH:" + libPath;
}

void ToolChainInvocation::addExtraLibPaths(StrList paths) {
    for( auto &libDir: paths )
    {
        this->libDirArgs.push_back(this->composeLibPathArg(libDir));
    }
}

StrList ToolChainInvocation::composeCommandLists(std::vector<StrList> command_args)
{
    StrList commandLine;
    for(auto arg_list : command_args)
    {
        commandLine.insert(commandLine.end(), arg_list.begin(), arg_list.end());
    }
    return commandLine;
}
