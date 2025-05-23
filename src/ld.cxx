/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "ld.h"
#include "winrpath.h"

void LdInvocation::LoadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->command = spackenv.SpackLD;
}


int LdInvocation::InvokeToolchain()
{
    // Run base linker invocation to produce initial
    // dll and import library
    int ret_code = ToolChainInvocation::InvokeToolchain();
    if(ret_code != 0){
        return ret_code;
    }
    // Next we want to construct the proper commmand line to
    // recreate the import library from the same set of obj files
    // and libs
    LinkerInvocation link_run(this->ComposeCommandLists({
        this->command_args,
        this->include_args,
        this->lib_args,
        this->lib_dir_args,
        this->obj_args
    }));
    link_run.Parse();
    // We're creating a dll, we need to create an appropriate import lib
    if(!link_run.IsExeLink()) {
        std::string basename = link_run.get_name();
        std::string imp_lib_name = link_run.get_implib_name();
        std::string dll_name = link_run.get_mangled_out();
        std::string abs_out_imp_lib_name = imp_lib_name + ".dll-abs.lib";
        std::string def_file = link_run.get_def_file();
        std::string def_line = "-def";
        def_line += !def_file.empty() ? ":" + def_file : "";
        // create command line to generate new import lib
        this->rpath_executor = ExecuteCommand("lib.exe", this->ComposeCommandLists(
            {
                {def_line, "-name:" + dll_name, "-out:"+ abs_out_imp_lib_name},
                this->obj_args,
                this->lib_args,
                this->lib_dir_args,
            }
        ));
        this->rpath_executor.Execute();
        int err_code = this->rpath_executor.Join();
        if(err_code != 0) {
            return err_code;
        }
        CoffReaderWriter cr(abs_out_imp_lib_name);
        CoffParser coff(&cr);
        if(!coff.Parse()) {
            debug("Failed to parse COFF file: " + abs_out_imp_lib_name);
            return -9;
        }
        if(!coff.NormalizeName(dll_name)){
            debug("Failed to normalize name for COFF file: " + abs_out_imp_lib_name);
            return -9;
        }
        debug("Renaming library from " + abs_out_imp_lib_name + " to " + imp_lib_name);
        std::remove(imp_lib_name.c_str());
        std::rename(abs_out_imp_lib_name.c_str(), imp_lib_name.c_str());
    }
    return ret_code;
}
