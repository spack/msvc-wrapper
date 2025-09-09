/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include "coff_parser.h"
#include "coff_reader_writer.h"
#include "commandline.h"
#include "spack_env.h"
#include "toolchain.h"
#include "toolchain_factory.h"
#include "utils.h"
#include "winrpath.h"
#include <Intsafe.h>

int main(int argc, const char* argv[]) {

    if (CheckAndPrintHelp(argv, argc)) {
        return 0;
    }
    if (IsRelocate(argv[0])) {
        std::map<std::string, std::string> patch_args =
            ParseRelocate(argv + 1, argc - 1);
        if (patch_args.empty()) {
            std::cerr << "Unable to parse command line for relocation\n"
                      << "run command with --help flag for accepted command "
                         "line arguments\n";
            return -1;
        }
        bool const full = !(patch_args.find("full") == patch_args.end());
        bool const deploy = !(patch_args.find("cmd") == patch_args.end()) &&
                            patch_args.at("cmd") == "deploy";
        bool const report = !(patch_args.find("report") == patch_args.end());
        bool const has_pe = !(patch_args.find("pe") == patch_args.end());
        bool const debug = !(patch_args.find("debug") == patch_args.end());
        bool const is_validate =
            !(patch_args.find("verify") == patch_args.end());
        bool const has_coff = !(patch_args.find("coff") == patch_args.end());
        // Without full with a DLL we re-produce the import lib from the
        // relocated DLL, but with an EXE there is nothing to do
        if (!has_coff && !has_pe) {
            std::cout << "No binaries to operate on... nothing to do\n";
            return ExitConditions::CLI_FAILURE;
        }
        // The only scenario its ok to have a dll/exe and no coff is when we're creating a cache
        // entry
        if (!has_coff && !deploy) {
            std::cout << "Attempting to relocate DLL without coff file, please "
                         "provide a coff file.\n";
            return ExitConditions::CLI_FAILURE;
        }
        if (is_validate && !has_coff) {
            std::cout << "Attempting to validate without a coff file, nothing "
                         "to validate\n";
            return ExitConditions::CLI_FAILURE;
        }
        if (report && !has_coff) {
            std::cout << "Attempting to report without a binary, nothing to "
                         "report...\n";
            return ExitConditions::CLI_FAILURE;
        }
        if (!(is_validate || report) && !has_pe) {
            std::cout << "Attempting to perform relocation without a PE file, "
                         "please provide one.\n";
            return ExitConditions::CLI_FAILURE;
        }
        if (is_validate) {
            return CoffParser::Validate(patch_args.at("coff"));
        }
        if (report) {
            CoffReaderWriter coff_reader(patch_args.at("coff"));
            CoffParser coff(&coff_reader);
            if (!reportCoff(coff)) {
                return ExitConditions::REPORT_FAILURE;
            }
            return ExitConditions::SUCCESS;
        }
        DEBUG = debug;
        std::unique_ptr<LibRename> rpath_lib;
        try {
            if (has_coff) {
                rpath_lib = std::make_unique<LibRename>(patch_args.at("pe"),
                                                        patch_args.at("coff"),
                                                        full, deploy, true);
            } else {
                rpath_lib = std::make_unique<LibRename>(patch_args.at("pe"),
                                                        full, deploy, true);
            }
        } catch (const NameTooLongError& e) {
            std::cerr << "Cannot Rename PE file " << patch_args.at("pe")
                      << " it contains references that are too long.\n";
            return ExitConditions::RENAME_FAILURE;
        }
        if (!rpath_lib->ExecuteRename()) {
            std::cerr << "Library rename failed\n";
            return ExitConditions::RENAME_FAILURE;
        }
    } else if (IsReport(argv[0])) {
        std::map<std::string, std::string> report_args =
            ParseReport(argc - 1, argv + 1);
        if (report_args.empty()) {
            std::cerr << "Unable to parse command line for reporting\n"
                      << "run command with --help flag for accepted command "
                         "line arguments\n";
            return ExitConditions::CLI_FAILURE;
        }
        if (report_args.find("pe") != report_args.end()) {
            try {
                LibRename portable_executable(
                    report_args.at("pe"), std::string(), false, false, true);
                portable_executable.ExecuteRename();
            } catch (const NameTooLongError& e) {
                std::cerr
                    << "Unable to parse command line for reporting\n"
                    << "run command with --help flag for accepted command "
                       "line arguments\n";
                return ExitConditions::CLI_FAILURE;
            }
        } else {
            CoffReaderWriter coff_reader(report_args.at("coff"));
            CoffParser coff(&coff_reader);
            return static_cast<int>(reportCoff(coff));
        }
    } else {
        // Ensure required variables are set
        if (!ValidateSpackEnv()) {
            return ExitConditions::INVALID_ENVIRONMENT;
        }
        // Determine which tool we're trying to run
        std::unique_ptr<ToolChainInvocation> const tchain(
            ToolChainFactory::ParseToolChain(argv));
        if (!tchain) {
            return ExitConditions::TOOLCHAIN_FAILURE;
        }
        // Establish Spack compiler/linker modifications from env
        SpackEnvState spack = SpackEnvState::LoadSpackEnvState();
        // Apply modifications to toolchain invocation
        tchain->InterpolateSpackEnv(spack);
        // Execute coolchain invocation
        int res;
        HRESULT const h_res = DWordToInt(tchain->InvokeToolchain(), &res);
        if (h_res == S_OK) {
            return res;
        }
        return h_res;
    }
    return ExitConditions::SUCCESS;
}
