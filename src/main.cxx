/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#include "toolchain_factory.h"
#include "winrpath.h"
#include "utils.h"
#include "commandline.h"

int main(int argc, const char* argv[]) {
    
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
        bool has_pe = !(patch_args.find("pe") == patch_args.end());
        bool is_exe = has_pe ? endswith(patch_args.at("pe"), ".exe") : false;
        bool debug = !(patch_args.find("debug") == patch_args.end());
        bool is_validate = !(patch_args.find("verify") == patch_args.end());
        bool has_coff = !(patch_args.find("coff") == patch_args.end());
        // Without full with a DLL we re-produce the import lib from the
        // relocated DLL, but with an EXE there is nothing to do
        if(!has_coff && !has_pe) {
            std::cout << "No binaries to operate on... nothing to do\n";
            return -1;
        }
        if (is_exe && !full)
        {
            std::cout << "Executable file provided but --full not specified, nothing to do...\n";
            return -1;
        }
        // The only scenario its ok to have a dll/exe and no coff is when we're creating a cache
        // entry
        if (!is_exe && !has_coff && !deploy) {
            std::cout << "Attempting to relocate DLL without coff file, please provide a coff file.\n";
            return -1;
        }
        if (is_validate && !has_coff) {
            std::cout << "Attempting to validate without a coff file, nothing to validate\n";
            return -1;
        }
        if (report && !has_coff) {
            std::cout << "Attempting to report without a binary, nothing to report...\n";
            return -1;
        }
        if (!(is_validate || report) && !has_pe) {
            std:: cout << "Attempting to perform relocation without a PE file, please provide one.\n";
            return -1;
        }
        if (is_validate) {
            return CoffParser::Validate(patch_args.at("coff"));
        }
        if (report) {
            CoffReaderWriter cr(patch_args.at("coff"));
            CoffParser coff(&cr);
            if(!reportCoff(coff)) {
                return 1;
            }
            return 0;
        }
        DEBUG = debug;
        std::unique_ptr<LibRename> rpath_lib;
        if (has_coff)
        {
            rpath_lib = std::make_unique<LibRename>(patch_args.at("pe"), patch_args.at("coff"), full, deploy, true);
        }
        else {
            rpath_lib = std::make_unique<LibRename>(patch_args.at("pe"), full, deploy, true);
        }
        if(!rpath_lib->ExecuteRename()){
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
            return reportCoff(coff);
        }
    }
    else {
        // Ensure required variables are set
        if(!ValidateSpackEnv()) {
            return -99;
        }
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
