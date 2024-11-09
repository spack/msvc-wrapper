#include "ld.h"

void LdInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = std::string("link.exe");
}
