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
#   all 	- default target, install + test, will be run if no target
#		        is provided to nmake
#   test    - 

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


{src}.cxx{}.obj::
	$(CC) /c $(CFLAGS) $(CVARS) /I:src $<	

{test}.cxx{test}.obj::
	$(CC) /c $(CFLAGS) $(CVARS) /I:test $<

all : install test

cl.exe : cl.obj execute.obj intel.obj ld.obj main.obj spack_env.obj toolchain.obj toolchain_factory.obj utils.obj winrpath.obj 
	link $(LFLAGS) $** Shlwapi.lib /out:cl.exe

install : cl.exe
	mkdir $(PREFIX)
	move cl.exe $(PREFIX)
	mklink $(PREFIX)/link.exe $(PREFIX)/cl.exe
	mklink $(PREFIX)/ifx.exe $(PREFIX)/cl.exe
	mklink $(PREFIX)/relocate.exe $(PREFIX)/cl.exe

setup_test: cl.exe
	del *.obj
	test\setup_spack_env.bat
	mkdir tmp\test
	cd tmp\test
	copy ..\..\cl.exe cl.exe
	mklink link.exe cl.exe
	mklink relocate.exe cl.exe
	cd ..\..

build_and_check_test_sample : setup_test
	cl /c /EHsc test\calc.cxx /DCALC_EXPORTS
	cl /c /EHsc test\main.cxx
	link $(LFLAGS) calc.obj /out:calc.dll /DLL
	link $(LFLAGS) main.obj calc.lib /out:tester.exe
	tester.exe
	cd ..

test : build_and_check_test_sample
	move test\tester.exe tmp\test\tester.exe
	tmp\test\tester.exe
	move calc.dll tmp\calc.dll
	test\run_failing_check.bat
	rmdir /q /s tmp


clean :
	del *.obj
	del *.exe
	del *.dll
	del *.lib
	del *.exp
	del *.pdb

clean-cl :
	del cl.exe
