#include "intel.h"

void FortranInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = spackenv.SpackFC;
}