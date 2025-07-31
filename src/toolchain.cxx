/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "toolchain.h"

#include <sstream>
#include <typeinfo>

ToolChainInvocation::ToolChainInvocation(std::string command,
                                         char const* const* cli)
    : command(command) {
    this->ParseCommandArgs(cli);
}

void ToolChainInvocation::InterpolateSpackEnv(SpackEnvState& spackenv) {
    // inject Spack includes before the default includes
    for (auto& include : spackenv.SpackIncludeDirs) {
        auto incArg = this->ComposeIncludeArg(include);
        this->include_args.insert(this->include_args.begin(), incArg);
    }
    for (auto& lib : spackenv.SpackLdLibs) {
        this->lib_args.push_back(lib);
    }
    this->AddExtraLibPaths(spackenv.SpackLinkDirs);
    this->AddExtraLibPaths(spackenv.SpackRPathDirs);
    this->AddExtraLibPaths(spackenv.SpackCompilerExtraRPaths);
    this->AddExtraLibPaths(spackenv.SpackCompilerImplicitRPaths);
    this->LoadToolchainDependentSpackVars(spackenv);
}

int ToolChainInvocation::InvokeToolchain() {
    StrList commandLine(this->ComposeCommandLists(
        {this->command_args, this->include_args, this->lib_args,
         this->lib_dir_args, this->obj_args}));
    this->executor = ExecuteCommand(this->command, commandLine);
    debug("Setting up executor for " + std::string(typeid(*this).name()) +
          "toolchain");
    debug("Toolchain: " + this->command);
    // Run first pass of command as requested by caller
    int ret_code = this->executor.Execute();
    if (!ret_code) {
        std::cerr << "Unable to launch toolchain process \n";
        return -9999;
    }
    return this->executor.Join();
}

void ToolChainInvocation::ParseCommandArgs(char const* const* cli) {
    // Collect include args as we need to ensure Spack
    // Includes come first
    for (char const* const* c = cli; *c; c++) {
        std::string arg = std::string(*c);
        if (startswith(arg, "/I") || startswith(arg, "-I")) {
            // We have an include arg
            // can have an optional space
            // check if there are characters after
            // "/I" and if not we consider the next
            // argument to be the include
            if (arg.size() > 2)
                this->include_args.push_back(arg);
            else {
                this->include_args.push_back(arg);
                this->include_args.push_back(std::string(*(++c)));
            }
        } else if (endswith(arg, ".lib") &&
                   (arg.find("implib:") == std::string::npos))
            // Lib args are just libraries
            // provided like system32.lib on the
            // command line.
            // lib specification order does not matter
            // on MSVC but this is useful for filtering system libs
            // and adding all libs
            this->lib_args.push_back(arg);
        else if (endswith(arg, ".obj"))
            this->obj_args.push_back(arg);
        else
            this->command_args.push_back(arg);
    }
}

std::string ToolChainInvocation::ComposeIncludeArg(std::string& include) {
    return "/external:I " + include;
}

std::string ToolChainInvocation::ComposeLibPathArg(std::string& libPath) {
    return "/LIBPATH:" + libPath;
}

void ToolChainInvocation::AddExtraLibPaths(StrList paths) {
    for (auto& libDir : paths) {
        this->lib_dir_args.push_back(this->ComposeLibPathArg(libDir));
    }
}

StrList ToolChainInvocation::ComposeCommandLists(
    std::vector<StrList> command_args) {
    StrList commandLine;
    for (auto arg_list : command_args) {
        // Ensure arguments are appropriately quoted
        quoteList(arg_list);
        commandLine.insert(commandLine.end(), arg_list.begin(), arg_list.end());
    }
    return commandLine;
}
