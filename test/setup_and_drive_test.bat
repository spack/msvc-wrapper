:: Copyright Spack Project Developers. See COPYRIGHT file for details.
::
:: SPDX-License-Identifier: (Apache-2.0 OR MIT)

@echo off
pushd %~dp0..
FOR /F "tokens=* USEBACKQ" %%F IN (`where cl`) DO (
SET SPACK_CC=%%F
)
FOR /F "tokens=* USEBACKQ" %%F IN (`where link`) DO (
SET SPACK_LD=%%F
)
popd
SET SPACK_COMPILER_WRAPPER_PATH=%~dp0..
SET SPACK_DEBUG_LOG_DIR=%CD%
SET SPACK_DEBUG_LOG_ID=TEST
SET SPACK_SHORT_SPEC=test%msvc
SET SPACK_SYSTEM_DIRS=%PATH%
SET SPACK_MANAGED_DIRS=%CD%\tmp

echo %SPACK_MANAGED_DIRS%

nmake test