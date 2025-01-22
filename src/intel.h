#pragma once

#include "toolchain.h"

/**
 * @brief ClInvocation exposes an interface driving invocations of
 * ifx.exe and defines the parameters of the call to said executable
 */
class FortranInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
protected:
    void LoadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "intel fortran";
};

