/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "toolchain_factory.h"
#include "cl.h"
#include "ld.h"
#include "intel.h"

std::unique_ptr<ToolChainInvocation> ToolChainFactory::ParseToolChain(char const* const * argv) {
    std::string command(*argv);
    char const* const* cli(++argv);
    StripPathAndExe(command);
    using lang = ToolChainFactory::Language;
    auto lang_it = SupportedTools.find(command);
    if (lang_it != SupportedTools.end())
    {
        ToolChainFactory::Language language = lang_it->second;
        std::unique_ptr<ToolChainInvocation> Tool;
        if(language == lang::cpp) {
            Tool = std::unique_ptr<ClInvocation>(new ClInvocation(command, cli));
        }
        else if(language == lang::Fortran) {
            Tool = std::unique_ptr<FortranInvocation>(new FortranInvocation(command, cli));
        }
        else if(language == lang::link) {
            // If it's not c/c++ or fortran, we're linking
            Tool = std::unique_ptr<LdInvocation>(new LdInvocation(command, cli));
        }
        else {
            std::cerr << "Unable to determine wrapper language or link context for " << command << "\n"; 
            return std::unique_ptr<ToolChainInvocation>(nullptr);
        }
        return Tool;
    }
    return std::unique_ptr<ToolChainInvocation>(nullptr);
}

const std::map<std::string, ToolChainFactory::Language> ToolChainFactory::SupportedTools{
                                                        {"cl", ToolChainFactory::Language::cpp},
                                                        {"link", ToolChainFactory::Language::link},
                                                        {"ifort", ToolChainFactory::Language::Fortran},
                                                        {"ifx", ToolChainFactory::Language::Fortran}
                                                    };


