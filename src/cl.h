/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include "utils.h"
#include "toolchain.h"


/**
 * @brief ClInvocation exposes an interface driving invocations of
 * cl.exe and defines the parameters of the call to said executable
 */
class ClInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
protected:
    void LoadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "c/c++";
};
