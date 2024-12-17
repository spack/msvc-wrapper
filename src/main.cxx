/**
 * @file main.cxx
 * @author John Parent (john.parent@kitware.com)
 * @brief A C++ wrapper file for the MSVC c and c++ compilers and linkers
 *        created for the Spack package manager.
 *
 *        This file implements the functionality required to inject Spack's build logic
 *        into the compiler/linker interface and drives the main entrypoint.
 * @date 2023-10-20
 *
 * @copyright  Copyright 2013-2024 Lawrence Livermore National Security, LLC and other
 *             Spack Project Developers. See the top-level COPYRIGHT file for details.
 *             SPDX-License-Identifier: (Apache-2.0 OR MIT)
 *
 */

#include "toolchain_factory.h"
#include "winrpath.h"
#include "utils.h"

int main(int argc, const char* argv[]) {
    if(checkAndPrintHelp(argv, argc)) {
        return 0;
    }
    if (isRelocate(argv[0])) {
        std::map<std::string, std::string> patch_args = parseRelocate(argv, argc);
        bool full = !patch_args.at("full").empty();
        bool deploy = patch_args.at("cmd") == "deploy";
        LibRename rpath_lib(patch_args.at("lib"), full, deploy, true);
        if(!rpath_lib.executeRename()){
            std::cerr << "Library rename failed\n";
            return 9;
        }
    }
    else {
        // Ensure required variables are set
        try {
            validate_spack_env();
        }
        catch (SpackCompilerContextException e)
        {
            std::cerr << "Spack compiler environment not properly established, please setup the environment and try again\n";
            return 99;
        }
        // Determine which tool we're trying to run
        std::unique_ptr<ToolChainInvocation> tchain(ToolChainFactory::ParseToolChain(argv));
        // Establish Spack compiler/linker modifications from env
        SpackEnvState spack = SpackEnvState::loadSpackEnvState();
        // Apply modifications to toolchain invocation
        tchain->interpolateSpackEnv(spack);
        // Execute coolchain invocation
        if (!tchain->invokeToolchain())
        {
            return 999;
        }
    }
    return 0;
}
