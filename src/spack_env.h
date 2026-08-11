/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
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
 *
 * This is loaded on every invocation of the wrapper, i.e. once per compiled
 * source file, so it deliberately reads only what the wrapper consumes.
 * Variables Spack sets that nothing here acts on are left unread rather than
 * being fetched and split into vectors that are immediately discarded.
 */
struct SpackEnvState {
    // NOTE: the four flag lists below are read from the environment but never
    // applied to any command line. That is an unimplemented feature (Spack's
    // per-package compiler flags are silently dropped)
    // see the note in LoadSpackEnvState.
    StrList SpackFFlags;
    StrList SpackCFlags;
    StrList SpackCxxFlags;
    StrList SpackLdFlags;

    StrList SpackLdLibs;
    StrList SpackCompilerExtraRPaths;
    StrList SpackCompilerImplicitRPaths;
    StrList SpackIncludeDirs;
    StrList SpackLinkDirs;
    StrList SpackRPathDirs;
    std::string SpackCC;
    // SpackCXX is unused in the current implementation
    // but is left here for future compatibility with
    // compilers with distinct c/cxx compilers unlink MSVC
    std::string SpackCXX;
    std::string SpackFC;
    std::string SpackF77;
    std::string SpackLD;

    /**
    * Loads spack related env variables from the environment
    * and returns a SpackEnvState object
    */
    static SpackEnvState LoadSpackEnvState();
};
