#include "intel.h"

void FortranInvocation::LoadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spack_command = spackenv.SpackFC;
}