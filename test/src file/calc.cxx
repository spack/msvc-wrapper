/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#if defined(CALC_HEADER)
#include CALC_HEADER /* "calc.h" */
#else
#include "calc header/calc.h"
#endif

extern "C" int add(int a, int b) {
    return a + b;
}