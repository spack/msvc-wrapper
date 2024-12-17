#pragma once

#include "utils.h"

struct SpackEnvState{
    std::string addDebugFlags;
    StrList SpackFFlags;
    StrList SpackCFlags;
    StrList SpackCxxFlags;
    StrList SpackLdFlags;
    StrList SpackLdLibs;
    StrList SpackCompilerExtraRPaths;
    StrList SpackCompilerImplicitRPaths;
    StrList SpackIncludeDirs;
    StrList SpackLinkDirs;
    StrList SpackCompilerFlagsKeep;
    StrList SpackCompilerFlagsReplace;
    StrList SpackEnvPath;
    StrList SpackSystemDirs;
    StrList SpackRPathDirs;
    std::string SpackCCRPathArg;
    std::string SpackCXXRPathArg;
    std::string SpackFCRPathArg;
    std::string SpackF77RPathArg;
    std::string SpackLinkerArg;
    std::string Spack;
    std::string SpackInstDir;
    std::string SpackCC;
    std::string SpackCXX;
    std::string SpackFC;
    std::string SpackF77;
    std::string SpackRoot;
    std::string SpackLD;

    static SpackEnvState loadSpackEnvState();
};