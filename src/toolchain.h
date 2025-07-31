/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include "execute.h"
#include "spack_env.h"
#include "utils.h"

/**
 * @brief
 */
class ToolChainInvocation {
   public:
    ToolChainInvocation(std::string command, char const* const* cli);

    virtual ~ToolChainInvocation() {}

    virtual void InterpolateSpackEnv(SpackEnvState& spackenv);
    virtual int InvokeToolchain();

   protected:
    virtual void ParseCommandArgs(char const* const* cli);
    virtual void LoadToolchainDependentSpackVars(SpackEnvState& spackenv) = 0;
    std::string ComposeIncludeArg(std::string& include);
    std::string ComposeLibPathArg(std::string& libPath);
    void AddExtraLibPaths(StrList paths);
    StrList ComposeCommandLists(std::vector<StrList> command_args);

    std::string command;
    std::string lang;
    StrList command_args;
    StrList include_args;
    StrList lib_dir_args;
    StrList lib_args;
    StrList obj_args;
    ExecuteCommand executor;
};
