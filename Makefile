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
BUILD_CFLAGS = /Zi -D_CRT_SECURE_NO_WARNINGS
BUILD_LINK = /DEBUG
!ENDIF

BASE_CFLAGS = /EHsc
CFLAGS = $(BASE_CFLAGS) $(BUILD_CFLAGS) $(CLFLAGS)
LFLAGS = $(BUILD_LINK) $(LINKFLAGS)

SRCS = cl.obj \
execute.obj \
intel.obj \
ld.obj \
main.obj \
spack_env.obj \
toolchain.obj \
toolchain_factory.obj \
utils.obj \
commandline.obj \
winrpath.obj \
coff_reader_writer.obj \
coff_parser.obj \
linker_invocation.obj


{src}.cxx{}.obj::
	"$(CC)" /c $(CFLAGS) $(CVARS) /I:src $<	

{test}.cxx{test}.obj::
	"$(CC)" /c $(CFLAGS) $(CVARS) /I:test $<

all : install test

cl.exe :  $(SRCS)
	link $(LFLAGS) $** Shlwapi.lib /out:cl.exe

install : cl.exe
	mkdir $(PREFIX)
	move cl.exe $(PREFIX)
	mklink $(PREFIX)\link.exe $(PREFIX)\cl.exe
	mklink $(PREFIX)\ifx.exe $(PREFIX)\cl.exe
	mklink $(PREFIX)\ifort.exe $(PREFIX)\ifort.exe
	mklink $(PREFIX)\relocate.exe $(PREFIX)\cl.exe

setup_test: cl.exe
	echo "-------------------"
	echo "Running Test Setup"
	echo "-------------------"
	-@ if NOT EXIST "tmp\test" mkdir "tmp\test"
	cd tmp\test
	copy ..\..\cl.exe cl.exe
	-@ if NOT EXIST "link.exe" mklink link.exe cl.exe
	cd ..\..

# smoke test - can the wrapper compile anything
# tests:
# * space in a path - preserved by quoted arguments
# * escaped quoted arguments
build_and_check_test_sample : setup_test
	echo "--------------------"
	echo "Building Test Sample"
	echo "--------------------"
	cd tmp\test
	cl /c /EHsc "..\..\test\src file\calc.cxx" /DCALC_EXPORTS /DCALC_HEADER="\"calc header/calc.h\"" /I ..\..\test\include
	cl /c /EHsc ..\..\test\main.cxx /I ..\..\test\include
	link $(LFLAGS) calc.obj /out:calc.dll /DLL
	link $(LFLAGS) main.obj calc.lib /out:tester.exe
	tester.exe
	cd ..\..

# Test basic wrapper behavior - did the absolute path to the DLL get injected
# into the executable
test_wrapper : build_and_check_test_sample
	echo "--------------------"
	echo "Running Wrapper Test"
	echo "--------------------"
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

# Test relocating an executable - re-write internal paths to dlls
test_relocate_exe: build_and_check_test_sample
	echo "--------------------------"
	echo "Running Relocate Exe Test"
	echo "--------------------------"
	cd tmp\test
	-@ if NOT EXIST "relocate.exe" mklink relocate.exe cl.exe
	move calc.dll ..\calc.dll
	relocate.exe --pe tester.exe --deploy --full
	relocate.exe --pe tester.exe --export --full
	tester.exe
	move ..\calc.dll calc.dll
	cd ../..

# Test relocating a dll - re-write import library
test_relocate_dll: build_and_check_test_sample
	echo "--------------------------"
	echo "Running Relocate DLL test"
	echo "--------------------------"
	cd tmp/test
	-@ if NOT EXIST "relocate.exe" mklink relocate.exe cl.exe
	cd ..
	mkdir tmp_bin
	mkdir tmp_lib
	move test\calc.dll tmp_bin\calc.dll
	move test\calc.lib tmp_lib\calc.lib
	test\relocate.exe --pe tmp_bin\calc.dll --coff tmp_lib\calc.lib --export
	cd test
	del tester.exe
	link main.obj ..\tmp_lib\calc.lib /out:tester.exe
	.\tester.exe
	cd ../..

test_pipe_overflow: build_and_check_test_sample
	echo "--------------------"
	echo " Pipe overflow test"
	echo "--------------------"
	set SPACK_CC_TMP=%SPACK_CC%
	set SPACK_CC=$(MAKEDIR)\test\lots-of-output.bat
	cl /c /EHsc "test\src file\calc.cxx"
	set SPACK_CC=%SPACK_CC_TMP%

build_zerowrite_test: test\writezero.obj
	link $(LFLAGS) $** Shlwapi.lib /out:writezero.exe

test_zerowrite: build_zerowrite_test
	echo "-----------------------"
	echo "Running zerowrite test"
	echo "-----------------------"
	set SPACK_CC_TMP=%SPACK_CC%
	set SPACK_CC=$(MAKEDIR)\writezero.exe
	cl /c EHsc "test\src file\calc.cxx"
	set SPACK_CC=%SPACK_CC_TMP%

test_long_paths: build_and_check_test_sample
	echo "------------------------"
	echo "Running long paths test"
	echo "------------------------"
	mkdir tmp\tmp\verylongdirectoryname\evenlongersubdirectoryname
	xcopy /E test\include tmp\tmp\verylongdirectoryname\evenlongersubdirectoryname
	xcopy /E "test\src file" tmp\tmp\verylongdirectoryname\evenlongersubdirectoryname
	xcopy test\main.cxx tmp\tmp\verylongdirectoryname\evenlongersubdirectoryname
	cd tmp\tmp\verylongdirectoryname\evenlongersubdirectoryname
	rename calc.cxx verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.cxx
	copy ..\..\..\..\cl.exe cl.exe
	-@ if NOT EXIST "link.exe" mklink link.exe cl.exe
	cl /c /EHsc "verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.cxx" /DCALC_EXPORTS /DCALC_HEADER="\"calc header/calc.h\"" /I include
	cl /c /EHsc main.cxx /I include
	link $(LFLAGS) verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.obj /DLL
	link $(LFLAGS) main.obj verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.lib /out:tester.exe
	tester.exe
	cd ../../../..

test_relocate_long_paths: test_long_paths
	echo "---------------------------------"
	echo "Running relocate logn paths test"
	echo "---------------------------------"
	cd tmp\tmp\verylongdirectoryname\evenlongersubdirectoryname
	-@ if NOT EXIST "relocate.exe" mklink relocate.exe cl.exe
	cd ..
	mkdir tmp_bin
	mkdir tmp_lib
	move evenlongersubdirectoryname\verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.dll tmp_bin\verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.dll
	move evenlongersubdirectoryname\verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.lib tmp_lib\verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.lib
	evenlongersubdirectoryname\relocate.exe --pe tmp_bin\verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.dll --coff tmp_lib\verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.lib --export
	cd evenlongersubdirectoryname
	del tester.exe
	link main.obj ..\tmp_lib\verylongfilepathnamethatwilldefinitelybegreaterthanonehundredandfourtyfourcharacters.lib /out:tester.exe
	.\tester.exe
	cd ../../../..

test_exe_with_exports:
	echo ------------------------------
	echo Running exe with exports test
	echo ------------------------------
	mkdir tmp\test\exe_with_exports
	xcopy /E test\include tmp\test\exe_with_exports
	xcopy /E "test\src file" tmp\test\exe_with_exports
	xcopy test\main2.h tmp\test\exe_with_exports
	xcopy test\main2.cxx tmp\test\exe_with_exports
	xcopy test\main3.cxx tmp\test\exe_with_exports
	cd tmp\test\exe_with_exports
	copy ..\..\..\cl.exe cl.exe
	-@ if NOT EXIST "link.exe" mklink link.exe cl.exe
	cl /c /EHsc "calc.cxx" /DCALC_EXPORTS /DCALC_HEADER="\"calc header/calc.h\"" /I include
	cl /c /EHsc main2.cxx /DMAIN_EXPORTS /I include
	cl /c /EHsc main3.cxx /I include
	link $(LFLAGS) calc.obj /out:calc.dll /DLL
	link $(LFLAGS) main2.obj calc.lib /out:tester1.exe
	link $(LFLAGS) main3.obj calc.lib tester1.lib /out:tester2.exe
	tester1.exe
	tester2.exe
	cd ../../..

test_def_file_name_override:
	mkdir tmp\test\def\def_override
	xcopy /E test\include tmp\test\def\def_override
	xcopy /E "test\src file" tmp\test\def\def_override
	xcopy test\main.cxx tmp\test\def\def_override
	xcopy test\calc.def tmp\test\def\def_override
	cd tmp\test\def\def_override
	copy ..\..\..\..\cl.exe cl.exe
	-@ if NOT EXIST "link.exe" mklink link.exe cl.exe
	cl /c /EHsc "calc.cxx" /DCALC_DEF_EXPORTS /DCALC_HEADER="\"calc header/calc.h\"" /I include
	cl /c /EHsc main.cxx /I include
# 	link $(LFLAGS) /DEF:calc.def calc.obj /DLL
# 	link $(LFLAGS) main.obj calcdef.lib /out:tester.exe
# 	tester.exe
	cd ../../../.. 

test_and_cleanup: test clean-test


test: test_wrapper test_relocate_exe test_relocate_dll test_def_file_name_override test_exe_with_exports test_long_paths test_pipe_overflow


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
	-@ if EXIST "tmp" rmdir /q /s "tmp"
	
