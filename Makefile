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
	mklink $(PREFIX)/relocate.exe $(PREFIX)/cl.exe

setup_test: cl.exe
	rmdir /q /s tmp
	mkdir tmp/test
	cd tmp/test
	# create symlinks to test the different toolchains
	copy ../../cl.exe cl.exe
	mklink link.exe cl.exe
	mklink relocate.exe cl.exe
	cd ../..

build_and_check_test_sample : test/calc.obj test/main.obj setup_test
	link $(LFLAGS) calc.obj /out:calc.dll /dll
	link $(LFLAGS) main.obj calc.lib /out:tester.exe
	tester.exe

test : build_and_check_test_sample
	move tester.exe tmp/test/tester.exe
	# if this runs the rpath hack worked
	tmp/test/tester.exe
	# now move the dll and make sure the test
	# executable fails
	# (sanity check)
	# need to wrap failure in bat file for nmake
	move calc.dll tmp/calc.dll
	test/run_failing_check.bat
	# now make sure relocate works
	tmp/test/relocate --executable tmp/test/tester.exe tmp
	tmp/test/tester.exe
	tmp/test/relocate --library tmp/calc.dll --full
	# validate that path is in the new binary
	link $(LFLAGS) main.obj tmp/calc.lib /out:tester.exe
	tester.exe

clean :
	del *.obj
	del *.exe
	del *.dll
	del *.lib

clean-cl :
	del cl.exe