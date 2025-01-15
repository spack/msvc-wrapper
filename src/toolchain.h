#pragma once

#include "utils.h"
#include "spack_env.h"
#include "execute.h"

/**
 * @brief
 */
class ToolChainInvocation{
public:
    ToolChainInvocation(std::string command, char const* const* cli);
    virtual ~ToolChainInvocation() {}
    virtual void interpolateSpackEnv(SpackEnvState &spackenv);
    virtual int invokeToolchain();
protected:
    virtual void parse_command_args(char const* const* cli);
    virtual void loadToolchainDependentSpackVars(SpackEnvState &spackenv) = 0;
    std::string composeIncludeArg(std::string &include);
    std::string composeLibPathArg(std::string &libPath);
    void addExtraLibPaths(StrList paths);
    std::string composeCLI();
    StrList composeCommandLists(std::vector<StrList> command_args);

    std::string command;
    std::string lang;
    StrList commandArgs;
    StrList includeArgs;
    StrList libDirArgs;
    StrList libArgs;
    StrList objArgs;
    ExecuteCommand executor;
    std::string spackCommand;
};
