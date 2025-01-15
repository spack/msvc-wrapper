#include "toolchain_factory.h"
#include "cl.h"
#include "ld.h"
#include "intel.h"

#include <algorithm>

std::unique_ptr<ToolChainInvocation> ToolChainFactory::ParseToolChain(char const* const * argv) {
    std::string command(*argv);
    char const* const* cli(++argv);
    stripPathandExe(command);
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
        else {
            // If it's not c/c++ or fortran we're linking
            Tool = std::unique_ptr<LdInvocation>(new LdInvocation(command, cli));
        }
        return Tool;
    }
    return std::unique_ptr<ToolChainInvocation>(nullptr);
}

void ToolChainFactory::stripPathandExe(std::string &command) {
    stripPath(command);
    stripExe(command);
};

void ToolChainFactory::stripExe(std::string &command) {
    // Normalize command to lowercase to avoid parsing issues
    std::transform(command.begin(), command.end(), command.begin(),
        [](unsigned char c){ return std::tolower(c); });
    std::string::size_type loc = command.rfind(".exe");
    if ( std::string::npos != loc )
        command.erase(loc);
}

void ToolChainFactory::stripPath(std::string &command) {
    command.erase(0, command.find_last_of("\\/") + 1);
}

const std::map<std::string, ToolChainFactory::Language> ToolChainFactory::SupportedTools{
                                                        {"cl", ToolChainFactory::Language::cpp},
                                                        {"link", ToolChainFactory::Language::link},
                                                        {"ifort", ToolChainFactory::Language::Fortran},
                                                        {"ifx", ToolChainFactory::Language::Fortran}
                                                    };


