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
 * @copyright  Copyright 2013-2023 Lawrence Livermore National Security, LLC and other
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
        LibRename rpath_lib(patch_args.at("lib"), patch_args.at("name"), true);
        rpath_lib.computeDefFile();
        rpath_lib.executeLibRename();
    }
    else {
        // Ensure required variables are set
        std::cout << "hi\n";
        // try {
        //     validate_spack_env();
        // }
        // catch (SpackCompilerContextException e)
        // {
        //     std::cerr << "Spack compiler environment not properly established, please setup the environment and try again\n";
        //     return 99;
        // }
        // Determine which tool we're trying to run
        std::cout << "hello\n";
        std::unique_ptr<ToolChainInvocation> tchain(ToolChainFactory::ParseToolChain(argv));
        std::cout << "auhweidiesn\n";
        // Establish Spack compiler/linker modifications from env
        SpackEnvState spack = SpackEnvState::loadSpackEnvState();
        std::cout << "goodbye\n";
        // Apply modifications to toolchain invocation
        tchain->interpolateSpackEnv(spack);
        std::cout << "adiuea\n";
        // Execute coolchain invocation
        tchain->invokeToolchain();
        std::cout << "BORK\n";
        // Any errors caused by the run are reported via the
        // toolchain, if we reach here, we've had success, exit
    }
    return 0;
}
