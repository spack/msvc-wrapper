/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "spack_env.h"
#include "utils.h"

SpackEnvState SpackEnvState::LoadSpackEnvState() {
    // For list type env variables, a second argument of
    // " " denotes this is a space separated env list
    SpackEnvState spackenv = SpackEnvState();
    spackenv.Spack = GetSpackEnv("SPACK");
    spackenv.SpackInstDir = GetSpackEnv("SPACKINSTDIR");
    spackenv.SpackCC = GetSpackEnv("SPACK_CC");
    spackenv.SpackCXX = GetSpackEnv("SPACK_CXX");
    spackenv.SpackFC = GetSpackEnv("SPACK_FC");
    spackenv.SpackF77 = GetSpackEnv("SPACK_F77");
    spackenv.SpackRoot = GetSpackEnv("SPACK_ROOT");
    spackenv.AddDebugFlags = GetSpackEnv("SPACK_ADD_DEBUG_FLAGS");
    spackenv.SpackFFlags = GetEnvList("SPACK_FFLAGS", " ");
    spackenv.SpackCFlags = GetEnvList("SPACK_CFLAGS", " ");
    spackenv.SpackCxxFlags = GetEnvList("SPACK_CXXFLAGS", " ");
    spackenv.SpackLdFlags = GetEnvList("SPACK_LDFLAGS", " ");
    spackenv.SpackLdLibs = GetEnvList("SPACK_LDLIBS", " ");
    spackenv.SpackCompilerExtraRPaths =
        GetEnvList("SPACK_COMPILER_EXTRA_RPATHS", "|");
    spackenv.SpackCompilerImplicitRPaths =
        GetEnvList("SPACK_COMPILER_IMPLICIT_RPATHS", "|");
    spackenv.SpackIncludeDirs = GetEnvList("SPACK_INCLUDE_DIRS", "|");
    spackenv.SpackLinkDirs = GetEnvList("SPACK_LINK_DIRS", "|");
    spackenv.SpackCompilerFlagsKeep =
        GetEnvList("SPACK_COMPILER_FLAGS_KEEP", "|");
    spackenv.SpackCompilerFlagsReplace =
        GetEnvList("SPACK_COMPILER_FLAGS_REPLACE", "|");
    spackenv.SpackEnvPath = GetEnvList("SPACK_ENV_PATH");
    spackenv.SpackCCRPathArg = GetSpackEnv("SPACK_CC_RPATH_ARG");
    spackenv.SpackCXXRPathArg = GetSpackEnv("SPACK_CXX_RPATH_ARG");
    spackenv.SpackFCRPathArg = GetSpackEnv("SPACK_FC_RPATH_ARG");
    spackenv.SpackF77RPathArg = GetSpackEnv("SPACK_F77_RPATH_ARG");
    spackenv.SpackSystemDirs = GetEnvList("SPACK_SYSTEM_DIRS", "|");
    spackenv.SpackRPathDirs = GetEnvList("SPACK_RPATH_DIRS", "|");
    spackenv.SpackLinkerArg = GetSpackEnv("SPACK_LINKER_ARG");
    spackenv.SpackLD = GetSpackEnv("SPACK_LD");
    return spackenv;
}