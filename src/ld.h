#pragma once

#include "toolchain.h"

/**
 * @brief ClInvocation exposes an interface driving invocations of
 * link.exe and defines the parameters of the call to said executable
 */
class LdInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
    virtual void invokeToolchain();
private:
    void loadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "link";
    ExecuteCommand rpath_executor;
};
