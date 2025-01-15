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
#ifdef __SANITIZE_ADDRESS__
    std::cout << "asan" << std::endl;
#endif
    
    if(checkAndPrintHelp(argv, argc)) {
        return 0;
    }
    if (isRelocate(argv[0])) {
        std::map<std::string, std::string> patch_args = parseRelocate(argv, argc);
        if(patch_args.empty()) {
            std::cerr << "Unable to parse command line for relocation\n" 
                << "run command with --help flag for accepted command line arguments\n";
            return -1;
        }
        bool full = !(patch_args.find("full") == patch_args.end());
        bool deploy = !(patch_args.find("cmd") == patch_args.end()) 
            && patch_args.at("cmd") == "deploy";
        LibRename rpath_lib(patch_args.at("pe"), full, deploy, true);
        if(!rpath_lib.executeRename()){
            std::cerr << "Library rename failed\n";
            return 9;
        }
    }
    else {
        // Ensure required variables are set
        // if(!validate_spack_env()) {
        //     return -99;
        // }
        // Determine which tool we're trying to run
        std::unique_ptr<ToolChainInvocation> tchain(ToolChainFactory::ParseToolChain(argv));
        if(!tchain) {
            return -3;
        }
        // Establish Spack compiler/linker modifications from env
        SpackEnvState spack = SpackEnvState::loadSpackEnvState();
        // Apply modifications to toolchain invocation
        tchain->interpolateSpackEnv(spack);
        // Execute coolchain invocation
        return tchain->invokeToolchain();
    }
    return 0;
}
