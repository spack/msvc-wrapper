#include "ld.h"
#include "winrpath.h"

void LdInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = std::string("link.exe");
}


void LdInvocation::invokeToolchain()
{
    // Run base linker invocation to produce initial
    // dll and import library
    ToolChainInvocation::invokeToolchain();
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
    // We're creating a dll, we need to create an appropriate import lib
    if(!link_run.is_exe_link()) {
        std::string imp_lib_name = link_run.get_name();
        std::string abs_imp_lib_name = strip(imp_lib_name, ".lib") + "-abs.lib";
        // create command line to generate new import lib
        ExecuteCommand exec("lib.exe", this->composeCommandLists(
            {
                {"-def", "-name", abs_imp_lib_name},
                this->objArgs,
                this->libArgs,
                this->libDirArgs,
            }
        ));
        exec.execute();
        CoffReader cr(abs_imp_lib_name);
        CoffParser coff(&cr);
        coff.parse();
        coff.normalize_name();
        // filesystem::rename removes 2nd arg if it exists and then
        // points the name at the file in the first arg
        std::filesystem::rename(abs_imp_lib_name.c_str(), imp_lib_name.c_str());
    }
}
