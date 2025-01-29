/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include "toolchain.h"

/**
 * @brief ClInvocation exposes an interface driving invocations of
 * link.exe and defines the parameters of the call to said executable
 */
class LdInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
    virtual int InvokeToolchain();
protected:
    void LoadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "link";
    ExecuteCommand rpath_executor;
};
