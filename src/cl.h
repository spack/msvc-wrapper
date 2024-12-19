/**
 * @file cl.hxx
 * @author John Parent (john.parent@kitware.com)
 * @brief A C++ wrapper header file for the MSVC c and c++ compilers and linkers
 *        created for the Spack package manager.
 *        Eclipses the names cl.exe and link.exe in the PATH during Spackc runtime,
 *        intercepting calls to the compiler/linker and injecting Spack specific logic
 *        and flags into the compiler and link interfaces for MSVC driven compilation
 *
 *        This header files specificies the interface with which the compiler
 *        wrapper interacts with the Spack build env, and the associated calls to
 *        the compiler and linker
 * @date 2023-10-20
 * @copyright  Copyright 2013-2023 Lawrence Livermore National Security, LLC and other
 *             Spack Project Developers. See the top-level COPYRIGHT file for details.
 *             SPDX-License-Identifier: (Apache-2.0 OR MIT)
 *
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
    void loadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "c/c++";
};
