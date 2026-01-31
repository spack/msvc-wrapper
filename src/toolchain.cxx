/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "toolchain.h"
#include <minwindef.h>

#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include "spack_env.h"
#include "utils.h"

ToolChainInvocation::ToolChainInvocation(std::string command,
                                         char const* const* cli)
    : command(std::move(command)) {
    this->ParseCommandArgs(cli);
}

void ToolChainInvocation::InterpolateSpackEnv(SpackEnvState& spackenv) {
    // inject Spack includes before the default includes
    for (auto& include : spackenv.SpackIncludeDirs) {
        auto inc_arg = ToolChainInvocation::ComposeIncludeArg(include);
        this->inputs.push_back(inc_arg);
    }
    for (auto& lib : spackenv.SpackLdLibs) {
        this->inputs.push_back(lib);
    }
    this->AddExtraLibPaths(spackenv.SpackLinkDirs);
    this->AddExtraLibPaths(spackenv.SpackRPathDirs);
    this->AddExtraLibPaths(spackenv.SpackCompilerExtraRPaths);
    this->AddExtraLibPaths(spackenv.SpackCompilerImplicitRPaths);
    this->LoadToolchainDependentSpackVars(spackenv);
}

DWORD ToolChainInvocation::InvokeToolchain() {
    quoteList(this->inputs);
    this->executor = ExecuteCommand(this->command, this->inputs);
    debug("Setting up executor for " + std::string(typeid(*this).name()) +
          "toolchain");
    debug("Toolchain: " + this->command);
    // Run first pass of command as requested by caller
    int const ret_code = static_cast<int>(this->executor.Execute());
    if (!ret_code) {
        std::cerr << "Unable to launch toolchain process \n";
        return ExitConditions::TOOLCHAIN_FAILURE;
    }
    return this->executor.Join();
}

void ToolChainInvocation::ParseCommandArgs(char const* const* cli) {
    for (char const* const* co = cli; *co; co++) {
        const std::string arg = std::string(*co);
        this->inputs.push_back(arg);
    }
}

std::string ToolChainInvocation::ComposeIncludeArg(std::string& include) {
    return "/external:I " + include;
}

std::string ToolChainInvocation::ComposeLibPathArg(std::string& libPath) {
    return "/LIBPATH:" + libPath;
}

void ToolChainInvocation::AddExtraLibPaths(StrList paths) {
    for (auto& lib_dir : paths) {
        this->inputs.push_back(ToolChainInvocation::ComposeLibPathArg(lib_dir));
    }
}

StrList ToolChainInvocation::ComposeCommandLists(
    const std::vector<StrList>& command_args) {
    StrList command_line;
    for (auto arg_list : command_args) {
        // Ensure arguments are appropriately quoted
        quoteList(arg_list);
        command_line.insert(command_line.end(), arg_list.begin(),
                            arg_list.end());
    }
    return command_line;
}
