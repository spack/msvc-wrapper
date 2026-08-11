# Building Spack's MSVC Compiler wrapper

## Requirements

1. MSVC

## Instructions

1. Navigate to the root of the compiler wrapper source (hint, it's the directory this file should be in)
1. nmake /f Makefile

The inference rule that compiles the sources looks for them in `src` relative to
the current directory, so run NMAKE from the source root rather than a separate
build directory.

With the last instruction, one of the targets can optionally be specified:
    * cl.exe
    * install
    Where install will build cl.exe and install it into $(CWD)/install from the makefiles'directory, or whereever PREFIX points to.

## Build configurations

The default build is **optimized**: `/O2 /Ob2 /Oi /GL /DNDEBUG /MT`, linked with
`/LTCG /OPT:REF /OPT:ICF`. This is not incidental - the wrapper is spawned once
per compiled source file and once per link for every package Spack builds, so an
unoptimized wrapper is a tax on every translation unit.

`BUILD_TYPE=debug` (or `DEBUG`) switches to `/Od /Zi /MTd` with `/DEBUG`.

NMAKE does not scan `#include` directives, so the Makefile declares every object
as depending on every header via `$(SRCS) : $(HEADERS)`. **Add new headers to
that list.** Without it, changing a struct layout or a function signature in a
header rebuilds only the like-named `.cxx` and leaves the other objects compiled
against the old declarations - which links without complaint and corrupts memory
at runtime.

## Variables that impact the build

In addition to the various standard NMAKE arguments accepted by default, this project will also accept:
    * CLFLAGS     - specify any flags to be passed to C++ compiler
    * CVARS       - specify any variables to be passed to C++ compiler
    * LINKFLAGS   - specify any linker flags
    * PREFIX      - denotes installation prefix for build artifacts, default is CWD\\install
    * BUILD_TYPE  - (one of debug or release), specifies configuration for build

## Measuring wrapper overhead

`test\bench_wrapper.ps1` reports the wrapper process' own CPU time against the
wrapped compile's wall time, plus batch wall clock at `-j1` and `-jN` against the
compiler invoked directly. Run it before and after any change to
`ExecuteCommand` or the per-invocation path.

```
powershell -ExecutionPolicy Bypass -File test\bench_wrapper.ps1
```
