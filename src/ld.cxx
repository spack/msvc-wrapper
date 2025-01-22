#include "ld.h"
#include "winrpath.h"

void LdInvocation::LoadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spack_command = spackenv.SpackLD;
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
        std::string imp_lib_name = strip(basename, ".dll") + ".lib";
        std::string dll_name = link_run.get_mangled_out();
        std::string abs_out_imp_lib_name = basename + ".dll-abs.lib";
        // create command line to generate new import lib
        this->rpath_executor = ExecuteCommand("lib.exe", this->ComposeCommandLists(
            {
                {"-def", "-name:" + dll_name, "-out:"+ abs_out_imp_lib_name},
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
        coff.Parse();
        if(!coff.NormalizeName(dll_name)){
            return -9;
        }
        std::remove(imp_lib_name.c_str());
        std::rename(abs_out_imp_lib_name.c_str(), imp_lib_name.c_str());

    }
    return ret_code;
}
