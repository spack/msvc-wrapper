#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

#include "version.h"
#include "utils.h"
#include "spack_env.h"
#include "execute.h"

class ToolChainInvocation{
public:
    ToolChainInvocation(std::string command, char const* const* cli);
    virtual ~ToolChainInvocation();
    virtual void interpolateSpackEnv(SpackEnvState &spackenv);
    virtual void invokeToolchain();
protected:
    virtual void parse_command_args(char const* const* cli);
    virtual void loadToolchainDependentSpackVars(SpackEnvState &spackenv) = 0;
    std::string composeIncludeArg(std::string &include);
    std::string composeLibPathArg(std::string &libPath);
    void addExtraLibPaths(StrList paths);
    std::string composeCLI();

    std::string command;
    std::string lang;
    StrList CommandArgs;
    StrList includeArgs;
    StrList libDirArgs;
    StrList libArgs;
    ExecuteCommand executor;
    std::string spackCommand;
};
