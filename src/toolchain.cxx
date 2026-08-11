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
    this->inputs.reserve(this->inputs.size() + spackenv.SpackIncludeDirs.size() +
                         spackenv.SpackLdLibs.size() +
                         spackenv.SpackLinkDirs.size() +
                         spackenv.SpackRPathDirs.size() +
                         spackenv.SpackCompilerExtraRPaths.size() +
                         spackenv.SpackCompilerImplicitRPaths.size());
    // inject Spack includes before the default includes
    for (auto& include : spackenv.SpackIncludeDirs) {
        this->inputs.push_back(
            ToolChainInvocation::ComposeIncludeArg(include));
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
    if (this->command.empty()) {
        std::cerr << "Spack compiler wrapper: no wrapped tool is configured "
                     "in the environment\n";
        return ExitConditions::INVALID_TOOLCHAIN;
    }
    if (IsSelf(this->command)) {
        // Spawning this would spawn another wrapper, and another, until the
        // machine runs out of processes. Fail loudly on the first one.
        std::cerr << "Spack compiler wrapper: refusing to invoke itself. The "
                     "environment points the wrapped tool at "
                  << this->command
                  << ", which is this wrapper. Set SPACK_CC/SPACK_CXX/SPACK_LD "
                     "to the real toolchain executables.\n";
        return ExitConditions::INVALID_TOOLCHAIN;
    }
    quoteList(this->inputs);
    this->executor = ExecuteCommand(this->command, this->inputs);
    DEBUG_LOG("Setting up executor for " + std::string(typeid(*this).name()) +
              "toolchain");
    DEBUG_LOG("Toolchain: " + this->command);
    // Run first pass of command as requested by caller
    int const ret_code = static_cast<int>(this->executor.Execute());
    if (!ret_code) {
        std::cerr << "Unable to launch toolchain process \n";
        return ExitConditions::TOOLCHAIN_FAILURE;
    }
    return this->executor.Join();
}

void ToolChainInvocation::ParseCommandArgs(char const* const* cli) {
    size_t argc = 0;
    for (char const* const* co = cli; *co; co++) {
        ++argc;
    }
    this->inputs.reserve(argc);
    for (char const* const* co = cli; *co; co++) {
        this->inputs.emplace_back(*co);
    }
}

std::string ToolChainInvocation::ComposeIncludeArg(const std::string& include) {
    return "/external:I\"" + include + "\"";
}

std::string ToolChainInvocation::ComposeLibPathArg(const std::string& libPath) {
    return "/LIBPATH:" + libPath;
}

void ToolChainInvocation::AddExtraLibPaths(const StrList& paths) {
    for (const auto& lib_dir : paths) {
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
