@echo off

nmake clean
nmake cl.exe BUILD_TYPE=DEBUG
mklink link.exe cl.exe
cl.exe /c test\calc.cxx /DCALC_EXPORTS