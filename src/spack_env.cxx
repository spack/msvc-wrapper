#include "spack_env.h"


SpackEnvState SpackEnvState::loadSpackEnvState() {
    SpackEnvState spackenv = SpackEnvState();
    spackenv.Spack = getSpackEnv("SPACK");
    spackenv.SpackInstDir = getSpackEnv("SPACKINSTDIR");
    spackenv.SpackCC = getSpackEnv("SPACK_CC");
    spackenv.SpackCXX = getSpackEnv("SPACK_CXX");
    spackenv.SpackFC = getSpackEnv("SPACK_FC");
    spackenv.SpackF77 = getSpackEnv("SPACK_F77");
    spackenv.SpackRoot = getSpackEnv("SPACK_ROOT");
    spackenv.addDebugFlags = getSpackEnv("SPACK_ADD_DEBUG_FLAGS");
    spackenv.SpackFFlags = getenvlist("SPACK_FFLAGS", " ");
    spackenv.SpackCFlags = getenvlist("SPACK_CFLAGS", " ");
    spackenv.SpackCxxFlags = getenvlist("SPACK_CXXFLAGS", " ");
    spackenv.SpackLdFlags = getenvlist("SPACK_LDFLAGS", " ");
    spackenv.SpackLdLibs = getenvlist("SPACK_LDLIBS", " ");
    spackenv.SpackCompilerExtraRPaths = getenvlist("SPACK_COMPILER_EXTRA_RPATHS", "|");
    spackenv.SpackCompilerImplicitRPaths = getenvlist("SPACK_COMPILER_IMPLICIT_RPATHS", "|");
    spackenv.SpackIncludeDirs = getenvlist("SPACK_INCLUDE_DIRS", "|");
    spackenv.SpackLinkDirs = getenvlist("SPACK_LINK_DIRS", "|");
    spackenv.SpackCompilerFlagsKeep = getenvlist("SPACK_COMPILER_FLAGS_KEEP", "|");
    spackenv.SpackCompilerFlagsReplace = getenvlist("SPACK_COMPILER_FLAGS_REPLACE", "|");
    spackenv.SpackEnvPath = getenvlist("SPACK_ENV_PATH");
    spackenv.SpackCCRPathArg = getSpackEnv("SPACK_CC_RPATH_ARG");
    spackenv.SpackCXXRPathArg = getSpackEnv("SPACK_CXX_RPATH_ARG");
    spackenv.SpackFCRPathArg = getSpackEnv("SPACK_FC_RPATH_ARG");
    spackenv.SpackF77RPathArg = getSpackEnv("SPACK_F77_RPATH_ARG");
    spackenv.SpackSystemDirs = getenvlist("SPACK_SYSTEM_DIRS", "|");
    spackenv.SpackRPathDirs = getenvlist("SPACK_RPATH_DIRS", "|");
    spackenv.SpackLinkerArg = getSpackEnv("SPACK_LINKER_ARG");
    spackenv.SpackLD = getSpackEnv("SPACK_LD");
    return spackenv;
}