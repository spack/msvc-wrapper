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
    spackenv.SpackCC = GetSpackEnv("SPACK_CC");
    spackenv.SpackCXX = GetSpackEnv("SPACK_CXX");
    spackenv.SpackFC = GetSpackEnv("SPACK_FC");
    spackenv.SpackF77 = GetSpackEnv("SPACK_F77");
    spackenv.SpackLD = GetSpackEnv("SPACK_LD");
    // TODO(johnwparent): nothing consumes these four - Spack's per-package
    // compiler and linker flags never reach the tool command line. They are
    // loaded here so the gap stays visible rather than silently disappearing.
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
    spackenv.SpackRPathDirs = GetEnvList("SPACK_RPATH_DIRS", "|");
    return spackenv;
}
