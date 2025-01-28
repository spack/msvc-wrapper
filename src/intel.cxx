#include "intel.h"

void FortranInvocation::LoadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->command = spackenv.SpackFC;
}