# Copyright 2013-2023 Lawrence Livermore National Security, LLC and other
# Spack Project Developers. See the top-level COPYRIGHT file for details.
# SPDX-License-Identifier: (Apache-2.0 OR MIT)

# Makefile (flavor nmake) for the MSVC compiler wrapper for the Spack package manager
# Useful arguments to be provided to nmake
# 	prefix 	    - denotes installation prefix for build artifacts, default is CWD\\install
# 	build_type  - (one of debug or release), specifies configuration for build
# 	clflags     - specify any flags to be passed to C++ compiler
# 	cvars       - specify any variables to be passed to C++ compiler
#   linkflags   - specify any linker flags
# Vendored targets:
# 	cl 		- builds just the compiler wrapper
# 	install - builds and installs the compiler wrapper
#   all 	- default target, same as install, will be run if no target
#		        is provided to nmake

!IFNDEF "$(PREFIX)"
PREFIX="$(MAKEDIR)\install\"
!ENDIF

!IF "$(BUILD_TYPE)" == "DEBUG"
BUILD_CFLAGS = /Zi
BUILD_LINK = /DEBUG
!ENDIF

BASE_CFLAGS = /EHsc
CFLAGS = $(BASE_CFLAGS) $(BUILD_CFLAGS) $(CLFLAGS)
LFLAGS = $(BUILD_LINK) $(LINKFLAGS)


.cxx.obj:
	$(CC) /c $(cflags) $(cvars) /I:src src/$*.cxx

all: install

cl.exe : cl.obj
	link $(LFLAGS) cl.obj /out:cl.exe

install : cl.exe
	mkdir $(PREFIX)
	copy cl.exe $(PREFIX)

build_test_driver: test/test_driver.obj
	rmdir /q /s tmp
	mkdir tmp
	lib $(LFLAGS) *.obj /out:wrapper.lib
	link $(LFLAGS) test/test_driver.obj wrapper.lib /out:driver.exe
	move driver.exe tmp/driver.exe

build_test_sample: test/calc.obj
	link $(LFLAGS) test/calc.obj /out:calc.dll /dll
	move calc.dll tmp/calc.dll

test: build_test_driver build_test_sample
	mkdir tmp/test && cd tmp/test
	move ../driver.exe .
	move ../calc.dll .
	# create symlinks to test the different toolchains
	copy ../..cl.exe cl.exe
	mklink /S link.exe cl.exe
	mklink /S ifx.exe cl.exe
	mklink /S relocate.exe cl.exe
	cl.exe /c ../../test/calc.cpp
	link.exe /dll calc.obj
	# driver.exe calc.dll


