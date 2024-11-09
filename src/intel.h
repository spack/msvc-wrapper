#pragma once

#include "toolchain.h"

/**
 * @brief ClInvocation exposes an interface driving invocations of
 * ifx.exe and defines the parameters of the call to said executable
 */
class IntelFortranInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
private:
    void loadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "intel fortran";
};

