#pragma once

#include "toolchain.h"

/**
 * @brief 
 */
class ToolChainFactory{
public:
    static std::unique_ptr<ToolChainInvocation> ParseToolChain(char const* const * argv);
private:
    static void StripPathAndExe(std::string &command);
    static void StripExe(std::string &command);
    static void StripPath(std::string &command);
    enum Language {
        cpp,
        Fortran,
        link
    };
    const static std::map<std::string, Language> SupportedTools;

};
