::rem Copyright Spack Project Developers. See COPYRIGHT file for details.
::
::rem SPDX-License-Identifier: (Apache-2.0 OR MIT)

@echo off

.\tester.exe
::rem We expect tester to fail here as we've 
::rem removed the DLL from the location for which we established
:: the rpath, this will ensure we don't get any false positives
:: errorlevel is the exit code variable nmake uses to determine if a command
:: has failed
if (%errorlevel% NEQ 0) (
    exit /b 0
)
else (
    exit /b 99
)
