/**
 * @file version.hxx
 * @author John Parent (john.parent@kitware.com)
 * @brief Versioning file for Spack MSVC compiler wrappers
 *        semantic versioning
 *        defines separate macro for major, minor, and patch
 *        versions, and a conjoined macro of major.minor.patch
 * @date 2023-11-02
 * @copyright  Copyright 2013-2023 Lawrence Livermore National Security, LLC and other
 *             Spack Project Developers. See the top-level COPYRIGHT file for details.
 *             SPDX-License-Identifier: (Apache-2.0 OR MIT)
 * 
 */
#pragma once

#define MSVC_WRAPPER_MAJOR 0
#define MSVC_WRAPPER_MINOR 1
#define MSVC_WRAPPER_PATCH 0

#define MSVC_WRAPPER_VERSION MSVC_WRAPPER_MAJOR.MSVC_WRAPPER_MINOR.MSVC_WRAPPER_PATCH
