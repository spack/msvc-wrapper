/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#include "toolchain_factory.h"
#include "winrpath.h"
#include "utils.h"

int main(int argc, const char* argv[]) {
#ifdef __SANITIZE_ADDRESS__
    std::cout << "asan" << std::endl;
#endif
    
    if(CheckAndPrintHelp(argv, argc)) {
        return 0;
    }
    if (IsRelocate(argv[0])) {
        std::map<std::string, std::string> patch_args = ParseRelocate(argv+1, argc-1);
        if(patch_args.empty()) {
            std::cerr << "Unable to parse command line for relocation\n" 
                << "run command with --help flag for accepted command line arguments\n";
            return -1;
        }
        bool full = !(patch_args.find("full") == patch_args.end());
        bool deploy = !(patch_args.find("cmd") == patch_args.end()) 
            && patch_args.at("cmd") == "deploy";
        bool report = !(patch_args.find("report") == patch_args.end());
        LibRename rpath_lib(patch_args.at("pe"), full, deploy, true, report);
        if(!rpath_lib.ExecuteRename()){
            std::cerr << "Library rename failed\n";
            return 9;
        }
    }
    else if(IsReport(argv[0])) {
        std::map<std::string, std::string> report_args = ParseReport(argc-1, argv+1);
        if (report_args.empty()) {
            std::cerr << "Unable to parse command line for reporting\n" 
            << "run command with --help flag for accepted command line arguments\n";
            return -1;
        }
        if (report_args.find("pe") != report_args.end()) {
            LibRename pe(report_args.at("pe"), false, false, false, true);
            pe.ExecuteRename();
        }
        else {
            CoffReaderWriter cr(report_args.at("coff"));
            CoffParser coff(&cr);
            coff.Parse();
            report_coff(coff);
        }
    }
    else {
        // Ensure required variables are set
        // if(!ValidateSpackEnv()) {
        //     return -99;
        // }
        // Determine which tool we're trying to run
        std::unique_ptr<ToolChainInvocation> tchain(ToolChainFactory::ParseToolChain(argv));
        if(!tchain) {
            return -3;
        }
        // Establish Spack compiler/linker modifications from env
        SpackEnvState spack = SpackEnvState::LoadSpackEnvState();
        // Apply modifications to toolchain invocation
        tchain->InterpolateSpackEnv(spack);
        // Execute coolchain invocation
        return tchain->InvokeToolchain();
    }
    return 0;
}
