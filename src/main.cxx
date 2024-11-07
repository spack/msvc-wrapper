#include "cl.h"
#include "winrpath.h"


int main(int argc, char* argv[]) {

    // int rpath = strcmp(argv[1], "rpath")
    // if (rpath) {
    //     CoffReader().relocate();
    // }
    // Ensure required variables are set
    // validate_spack_env();
    // Determine which tool we're trying to run
    std::unique_ptr<ToolChainInvocation> tchain(ToolChainFactory::ParseToolChain(argv));
    // Establish Spack compiler/linker modifications from env
    SpackEnvState spack = SpackEnvState::loadSpackEnvState();
    // Apply modifications to toolchain invocation
    tchain->interpolateSpackEnv(spack);
    // Execute coolchain invocation
    tchain->invokeToolchain();
    // Any errors caused by the run are reported via the
    // toolchain, if we reach here, we've had success, exit
    return 0;
}
