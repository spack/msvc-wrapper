/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "ld.h"
#include <minwindef.h>
#include <cstdio>
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
    // Run base linker invocation to produce initial
    // dll and import library
    DWORD const ret_code = ToolChainInvocation::InvokeToolchain();
    if (ret_code != 0) {
        return ret_code;
    }
    // Next we want to construct the proper commmand line to
    // recreate the import library from the same set of obj files
    // and libs
    LinkerInvocation link_run(LdInvocation::ComposeCommandLists(
        {this->command_args, this->include_args, this->lib_args,
         this->lib_dir_args, this->obj_args}));
    link_run.Parse();
    // We're creating a dll, we need to create an appropriate import lib
    if (!link_run.IsExeLink()) {
        std::string const imp_lib_name = link_run.get_implib_name();
        std::string dll_name = link_run.get_mangled_out();
        std::string const abs_out_imp_lib_name = imp_lib_name + ".dll-abs.lib";
        std::string const def_file = link_run.get_def_file();
        std::string def_line = "-def";
        def_line += !def_file.empty() ? ":" + def_file : "";
        // create command line to generate new import lib
        this->rpath_executor = ExecuteCommand(
            "lib.exe",
            LdInvocation::ComposeCommandLists({
                {def_line, "-name:" + dll_name, "-out:" + abs_out_imp_lib_name},
                {link_run.get_rsp_file()},
                this->obj_args,
                this->lib_args,
                this->lib_dir_args,
            }));
        this->rpath_executor.Execute();
        DWORD const err_code = this->rpath_executor.Join();
        if (err_code != 0) {
            return err_code;
        }
        CoffReaderWriter coff_reader(abs_out_imp_lib_name);
        CoffParser coff(&coff_reader);
        if (!coff.Parse()) {
            debug("Failed to parse COFF file: " + abs_out_imp_lib_name);
            return 9;
        }
        if (!coff.NormalizeName(dll_name)) {
            debug("Failed to normalize name for COFF file: " +
                  abs_out_imp_lib_name);
            return 9;
        }
        debug("Renaming library from " + abs_out_imp_lib_name + " to " +
              imp_lib_name);
        int const remove_exitcode = std::remove(imp_lib_name.c_str());
        if (remove_exitcode) {
            debug("Failed to remove original import library with exit code: " +
                  remove_exitcode);
            return 10;
        }
        int const rename_exitcode =
            std::rename(abs_out_imp_lib_name.c_str(), imp_lib_name.c_str());
        if (rename_exitcode) {
            debug("Failed to rename temporary import library with exit code: " +
                  rename_exitcode);
            return 11;
        }
    }
    return ret_code;
}
