/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#ifdef MAIN_EXPORTS
#define MAIN_API __declspec(dllexport)
#else
#define MAIN_API __declspec(dllimport)
#endif

extern "C" MAIN_API int sub(const int& a, const int& b);