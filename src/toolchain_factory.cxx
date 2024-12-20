#include "toolchain_factory.h"
#include "cl.h"
#include "ld.h"
#include "intel.h"

std::unique_ptr<ToolChainInvocation> ToolChainFactory::ParseToolChain(char const* const * argv) {
    std::string command(*argv);
    char const* const* cli(++argv);
    stripPathandExe(command);
    using lang = ToolChainFactory::Language;
    try {
        ToolChainFactory::Language language = SupportedTools.at(command);
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
    } catch (std::out_of_range& e) {
        throw SpackUnknownCompilerException(command);
    }
}

void ToolChainFactory::stripPathandExe(std::string &command) {
    stripPath(command);
    stripExe(command);
};

void ToolChainFactory::stripExe(std::string &command) {
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


