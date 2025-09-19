
/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "cl.h"
#include "spack_env.h"

void ClInvocation::LoadToolchainDependentSpackVars(SpackEnvState& spackenv) {
    // C and CXX compiler executables are the same for MSVC (both cl, hence the class name)
    // However, depending on how a package depends on the languages, one or both
    // may be present in the env. Arbitrarily prefer the C compiler as the choice
    // truly doesn't matter
    this->command =
        !spackenv.SpackCC.empty() ? spackenv.SpackCC : spackenv.SpackCXX;
}
