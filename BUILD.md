# Building Spack's MSVC Compiler wrapper

## Requirements

1. MSVC

## Instructions

1. Navigate to the root of the compiler wrapper source (hint, it's the directory this file should be in)
1. `mkdir .\build && cd build`
1. nmake /f ..\Makefile

With the last instruction, one of the targets can optionally be specified:
    * cl.exe
    * install
    Where install will build cl.exe and install it into $(CWD)/install from the makefiles'directory, or whereever PREFIX points to.

## Variables that impact the build

In addition to the various standard NMAKE arguments accepted by default, this project will also accept:
    * CLFLAGS     - specify any flags to be passed to C++ compiler
    * CVARS       - specify any variables to be passed to C++ compiler
    * LINKFLAGS   - specify any linker flags
    * PREFIX      - denotes installation prefix for build artifacts, default is CWD\\install
    * BUILD_TYPE  - (one of debug or release), specifies configuration for build
