/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include "toolchain.h"
#include "utils.h"
/**
 * @brief 
 */
class ToolChainFactory{
public:
    static std::unique_ptr<ToolChainInvocation> ParseToolChain(char const* const * argv);
private:
    enum Language {
        cpp,
        Fortran,
        link
    };
    const static std::map<std::string, Language> SupportedTools;

};
