/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include <memory>

#include <iostream>
#include <map>
#include <string>
#include "cl.h"
#include "intel.h"
#include "ld.h"
#include "toolchain.h"
#include "toolchain_factory.h"
#include "utils.h"

std::unique_ptr<ToolChainInvocation> ToolChainFactory::ParseToolChain(
    char const* const* argv) {
    std::string command(*argv);
    char const* const* cli(++argv);
    StripPathAndExe(command);
    using lang = ToolChainFactory::Language;
    auto lang_it = SupportedTools.find(command);
    if (lang_it != SupportedTools.end()) {
        ToolChainFactory::Language const language = lang_it->second;
        std::unique_ptr<ToolChainInvocation> tool;
        if (language == lang::cpp) {
            tool = std::make_unique<ClInvocation>(command, cli);
        } else if (language == lang::Fortran) {
            tool = std::make_unique<FortranInvocation>(command, cli);
        } else if (language == lang::link) {
            // If it's not c/c++ or fortran, we're linking
            tool = std::make_unique<LdInvocation>(command, cli);
        } else {
            std::cerr
                << "Unable to determine wrapper language or link context for "
                << command << "\n";
            return std::unique_ptr<ToolChainInvocation>(nullptr);
        }
        return tool;
    }
    return std::unique_ptr<ToolChainInvocation>(nullptr);
}

const std::map<std::string, ToolChainFactory::Language>
    ToolChainFactory::SupportedTools{
        {"cl", ToolChainFactory::Language::cpp},
        {"link", ToolChainFactory::Language::link},
        {"ifort", ToolChainFactory::Language::Fortran},
        {"ifx", ToolChainFactory::Language::Fortran}};
