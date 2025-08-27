/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "intel.h"
#include "spack_env.h"

void FortranInvocation::LoadToolchainDependentSpackVars(
    SpackEnvState& spackenv) {
    this->command = spackenv.SpackFC;
}