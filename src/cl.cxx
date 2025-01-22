#include "cl.h"

void ClInvocation::LoadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spack_command = spackenv.SpackCC;
}
