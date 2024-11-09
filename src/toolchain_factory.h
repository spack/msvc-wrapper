#pragma once

#include "toolchain.h"

class ToolChainFactory{
public:
    static std::unique_ptr<ToolChainInvocation> ParseToolChain(char const* const * argv);
private:
    static void stripPathandExe(std::string &command);
    static void stripExe(std::string &command);
    static void stripPath(std::string &command);
    enum Language {
        cpp,
        intelFortran,
        link
    };
    const static std::map<std::string, Language> SupportedTools;

};
