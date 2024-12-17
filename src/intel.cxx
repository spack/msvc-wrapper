#include "intel.h"

void IntelFortranInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = spackenv.SpackFC;
}