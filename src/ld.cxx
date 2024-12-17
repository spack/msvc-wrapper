#include "ld.h"
#include "winrpath.h"

void LdInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = std::string("C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.42.34433\\bin\\Hostx64\\x64\\link.exe");
}


int LdInvocation::invokeToolchain()
{
    // Run base linker invocation to produce initial
    // dll and import library
    if(!ToolChainInvocation::invokeToolchain()){
        std::cerr << "Unable to complete initial linker pass. ";
        std::cerr << "Skipping re-name operation.\n";
        return 0;
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
        try{
            this->rpath_executor.execute();
            CoffReader cr(abs_out_imp_lib_name);
            CoffParser coff(&cr);
            coff.parse();
            coff.normalize_name();
        }
        catch(SpackException &e){
            std::cerr << "Failed to execute rename and normalization with error: " << e.what() << "\n";
            return 0;
        }
        std::rename(abs_out_imp_lib_name.c_str(), imp_lib_name.c_str());
    }
    return 1;
}
