
/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "cl.h"

void ClInvocation::LoadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->command = spackenv.SpackCC;
}
