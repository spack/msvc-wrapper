#include "cl.h"

void ClInvocation::LoadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->command = spackenv.SpackCC;
}
