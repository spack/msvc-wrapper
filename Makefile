# Copyright Spack Project Developers. See COPYRIGHT file for details.
#
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

cl.exe : cl.obj execute.obj intel.obj ld.obj main.obj spack_env.obj toolchain.obj toolchain_factory.obj utils.obj commandline.obj winrpath.obj 
	link $(LFLAGS) $** Shlwapi.lib /out:cl.exe

install : cl.exe
	mkdir $(PREFIX)
	move cl.exe $(PREFIX)
	mklink $(PREFIX)\link.exe $(PREFIX)\cl.exe
	mklink $(PREFIX)\ifx.exe $(PREFIX)\cl.exe
	mklink $(PREFIX)\ifort.exe $(PREFIX)\ifort.exe
	mklink $(PREFIX)\relocate.exe $(PREFIX)\cl.exe

setup_test: cl.exe
	-@ if NOT EXIST "tmp\test" mkdir "tmp\test"
	cd tmp\test
	copy ..\..\cl.exe cl.exe
	-@ if NOT EXIST "link.exe" mklink link.exe cl.exe
	cd ..\..

build_and_check_test_sample : setup_test
	cd tmp\test
	cl /c /EHsc ..\..\test\calc.cxx /DCALC_EXPORTS
	cl /c /EHsc ..\..\test\main.cxx
	link $(LFLAGS) calc.obj /out:calc.dll /DLL
	link $(LFLAGS) main.obj calc.lib /out:tester.exe
	tester.exe
	cd ..\..

test_wrapper : build_and_check_test_sample
	cd tmp
	move test\tester.exe .\tester.exe
	.\tester.exe
	mkdir tmp_bin
	move test\calc.dll tmp_bin\calc.dll
	..\test\run_failing_check.bat
	move tmp_bin\calc.dll test\calc.dll
	move tester.exe test\tester.exe
	rmdir /q /s tmp_bin
	cd ..

test_relocate: build_and_check_test_sample
	cd tmp\test
	-@ if NOT EXIST "relocate.exe" mklink relocate.exe cl.exe
	move calc.dll ..\calc.dll
	relocate.exe tester.exe --deploy --full
	relocate.exe tester.exe --export --full
	tester.exe

test: test_wrapper test_relocate 


clean : clean-test clean-cl
	del *.obj
	del *.exe
	del *.dll
	del *.lib
	del *.exp
	del *.pdb
	del *.ilk

clean-cl :
	del cl.exe

clean-test:
	rmdir /q /s tmp
