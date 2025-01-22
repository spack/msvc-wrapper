#pragma once

#include "utils.h"

/**
 * Loads Spack relevant variables from the environment
 * into the compiler wrapper for easy access
 * with convenient interface.
 * 
 * ENV variables that are lists are decomposed as such
 * by this method and are accessible as c++ lists
 * Variables that are simple strings are also treated as such
 */
struct SpackEnvState{
    std::string AddDebugFlags;
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
    // SpackCXX is unused in the current implementation
    // but is left here for future compatibility with
    // compilers with distinct c/cxx compilers unlink MSVC
    std::string SpackCXX; 
    std::string SpackFC;
    std::string SpackF77;
    std::string SpackRoot;
    std::string SpackLD;

    /**
    * Loads spack related env variables from the environment
    * and returns a SpackEnvState object
    */
    static SpackEnvState LoadSpackEnvState();
};