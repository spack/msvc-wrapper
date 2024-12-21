#include "ld.h"
#include "winrpath.h"

void LdInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = spackenv.SpackLD;
}


int LdInvocation::invokeToolchain()
{
    // Run base linker invocation to produce initial
    // dll and import library
    int ret_code = ToolChainInvocation::invokeToolchain();
    if(ret_code != 0){
        return ret_code;
    }
    // Next we want to construct the proper commmand line to
    // recreate the import library from the same set of obj files
    // and libs
    LinkerInvocation link_run(this->composeCommandLists({
        this->commandArgs,
        this->includeArgs,
        this->libArgs,
        this->libDirArgs,
        this->objArgs
    }));
    link_run.parse();
    // We're creating a dll, we need to create an appropriate import lib
    if(!link_run.is_exe_link()) {
        std::string basename = link_run.get_name();
        std::string imp_lib_name = strip(basename, ".dll") + ".lib";
        std::string dll_name = link_run.get_mangled_out();
        std::string abs_out_imp_lib_name = basename + ".dll-abs.lib";
        // create command line to generate new import lib
        this->rpath_executor = ExecuteCommand("lib.exe", this->composeCommandLists(
            {
                {"-def", "-name:" + dll_name, "-out:"+ abs_out_imp_lib_name},
                this->objArgs,
                this->libArgs,
                this->libDirArgs,
            }
        ));
        this->rpath_executor.execute();
        int err_code = this->rpath_executor.join();
        if(err_code != 0) {
            return err_code;
        }
        CoffReader cr(abs_out_imp_lib_name);
        CoffParser coff(&cr);
        coff.parse();
        coff.normalize_name();
        std::remove(imp_lib_name.c_str());
        std::rename(abs_out_imp_lib_name.c_str(), imp_lib_name.c_str());

    }
    return ret_code;
}
