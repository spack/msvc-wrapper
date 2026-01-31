/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "ld.h"
#include <minwindef.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include "coff_parser.h"
#include "coff_reader_writer.h"
#include "linker_invocation.h"
#include "spack_env.h"
#include "toolchain.h"
#include "utils.h"

void LdInvocation::LoadToolchainDependentSpackVars(SpackEnvState& spackenv) {
    this->command = spackenv.SpackLD;
}

DWORD LdInvocation::InvokeToolchain() {
    // Run a pass of the linker

    // First parse the linker command line to
    // understand what we'll be doing
    LinkerInvocation link_run(this->inputs);
    link_run.Parse();
    std::string rc_file;
    try {
        // Run resource compiler to create
        // Resource for id'ing binary when relocating its import library
        rc_file = LdInvocation::createRC(link_run);
    } catch (const RCCompilerFailure& e) {
        return ExitConditions::TOOLCHAIN_FAILURE;
    }

    // Add produced RC file to linker CLI to inject ID
    // This needs to be at the end of either libs or objs or rsp files
    // so long as this RC file is not the first binary
    // file the linker sees (or is referenced in the case of an rsp)
    // otherwise this resource file will dictate the binairies
    // name, which will break client expectations
    this->inputs.push_back(rc_file);
    // Run base linker invocation to produce initial
    // dll and import library
    DWORD const ret_code = ToolChainInvocation::InvokeToolchain();
    if (ret_code != 0) {
        return ret_code;
    }

    // We're creating a PE, we need to create an appropriate import lib
    std::string const imp_lib_name = link_run.get_implib_name();

    // Next we want to construct the proper commmand line to
    // recreate the import library from the same set of obj files
    // and libs

    // first determine if this link run created the import library
    // check if the import library that *might* be produced
    // by this run (given input argument construction)
    // exists. Multiple link runs could in theory produce the name
    // imp lib (or at least with the same name)
    // i.e. link /out:perl.exe perl.lib
    // and link /out:perl.dll perl.lib /DLL could both in theory
    // produce the same import library

    // If there is no implib, we don't need to bother
    // trying to rename
    if (!fileExists(imp_lib_name)) {
        // There are numerous contexts in which a PE file
        // may not export symbols, some are bugs in the
        // upstream project, most are valid, all are not
        // the concern of this wrapper
        return 0;
    }
    // There is an imp lib, so
    // Check if the imp lib is associated with the link command
    // we just ran, if we cannot process the coff file
    // we should exit with failure since something is unexpected
    {
        // Create temp scope to ensure all handles are appropriately deallocated
        // since the Coff readers use RAII
        CoffReaderWriter existing_coff_reader(imp_lib_name);
        CoffParser existing_coff(&existing_coff_reader);
        if (!existing_coff.Parse()) {
            std::cerr << "Unable to parse coff file: " << imp_lib_name
                      << " unable to determine import library provenance\n";
            return ExitConditions::COFF_PARSE_FAILURE;
        }
        std::string const shorter_name = existing_coff.GetName();
        std::string const link_name = basename(link_run.get_out());
        if (shorter_name.empty() || link_name.empty()) {
            debug("Cannot determine either PE or COFF names (Pe: " + link_name +
                  "; Coff: " + shorter_name + ") skipping absolute rename\n");
        }

        if (shorter_name != link_name) {
            debug("internal lib name: " + shorter_name +
                  " Pe name: " + link_name + " are not equivalent");
            return 0;
        }
        existing_coff_reader.Close();
    }

    std::string pe_name;
    try {
        pe_name = link_run.get_mangled_out();
    } catch (const NameTooLongError& e) {
        std::cerr << "Unable to mangle PE " << link_run.get_out()
                  << " name is too long\n";
        return ExitConditions::NORMALIZE_NAME_FAILURE;
    }
    std::string const abs_out_imp_lib_name = imp_lib_name + ".pe-abs.lib";
    std::string const def_file = link_run.get_def_file();
    std::string const def = "-def" + (def_file.empty() ? " " : ":" + def_file);
    std::string piped_args = link_run.get_lib_link_args();
    // create command line to generate new import lib
    this->rpath_executor = ExecuteCommand(
        "lib.exe",
        LdInvocation::ComposeCommandLists({{def, piped_args, "-name:" + pe_name,
                                            "-out:" + abs_out_imp_lib_name},
                                           link_run.get_input_files()}));
    this->rpath_executor.Execute();
    DWORD const err_code = this->rpath_executor.Join();
    if (err_code != 0) {
        return err_code;
    }
    CoffReaderWriter coff_reader(abs_out_imp_lib_name);
    CoffParser coff(&coff_reader);
    debug("Parsing COFF file: " + abs_out_imp_lib_name);
    if (!coff.Parse()) {
        debug("Failed to parse COFF file: " + abs_out_imp_lib_name);
        return ExitConditions::COFF_PARSE_FAILURE;
    }
    debug("COFF file parsed");
    debug("Normalizing coff file for name: " + pe_name);
    if (!coff.NormalizeName(pe_name)) {
        debug("Failed to normalize name for COFF file: " +
              abs_out_imp_lib_name);
        return ExitConditions::NORMALIZE_NAME_FAILURE;
    }
    debug("Renaming library from " + abs_out_imp_lib_name + " to " +
          imp_lib_name);
    int const remove_exitcode = std::remove(imp_lib_name.c_str());
    if (remove_exitcode) {
        debug("Failed to remove original import library with exit code: " +
              remove_exitcode);
        return ExitConditions::LIB_REMOVE_FAILURE;
    }
    int const rename_exitcode =
        std::rename(abs_out_imp_lib_name.c_str(), imp_lib_name.c_str());
    if (rename_exitcode) {
        debug("Failed to rename temporary import library with exit code: " +
              rename_exitcode);
        return ExitConditions::FILE_RENAME_FAILURE;
    }
    return ret_code;
}

std::string LdInvocation::createRC(LinkerInvocation& link_run) {
    const std::string pe_stage_name = link_run.get_out();
    const std::string template_base =
        "spack SPACKRESOURCE\n"
        "BEGIN\n";
    const std::string template_end = "END\n";
    const std::string pe_name = stripLastExt(basename(pe_stage_name));
    const std::string rc_file_name = "spack-" + pe_name + ".rc";
    // This res file name needs to mirror the PE name _exactly_
    // Otherwise the RC file will override the default
    // or user set name, violating user expectation
    std::string res_file_name = pe_name + ".res";
    if (!link_run.get_rc_files().empty()) {
        res_file_name = "spack-" + res_file_name;
    }

    ExecuteCommand rc_executor("rc",
                               {"/fo" + res_file_name + " " + rc_file_name});
    std::ofstream rc_out(rc_file_name);
    if (!rc_out) {
        std::cerr << "Error: could not open rc file for creation: "
                  << rc_file_name << "\n";
        throw RCCompilerFailure("Could not open RC file");
    }
    std::string abs_out = EnsureValidLengthPath(
        CannonicalizePath(MakePathAbsolute(pe_stage_name)));
    char* chr_abs_out = new char[abs_out.length() + 1];
    strcpy(chr_abs_out, abs_out.c_str());
    char* padded_path =
        pad_path(chr_abs_out, static_cast<DWORD>(abs_out.length()), '\\');
    abs_out = std::string(padded_path, MAX_NAME_LEN);
    free(chr_abs_out);
    free(padded_path);
    abs_out = escape_backslash(abs_out);
    rc_out << template_base << "    " << '"' << abs_out << '"' << "\n"
           << template_end;
    rc_out.close();
    rc_executor.Execute();
    DWORD const err_code = rc_executor.Join();
    if (err_code != 0) {
        throw RCCompilerFailure("Could not compile RC file");
    }
    return res_file_name;
}
