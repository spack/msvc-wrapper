/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "main2.h"
#include "calc header/calc.h"

extern "C" int sub(const int& a, const int& b) {
    return a - b;
}

int main(int /*argc*/, char** /*argv*/) {
    add(1, 2);
    sub(2, 1);
    return 0;
}