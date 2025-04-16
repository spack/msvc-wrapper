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
SET SPACK_ENV_PATH=%PATH%
SET SPACK_DEBUG_LOG_DIR=%CD%
SET SPACK_COMPILER_SPEC=%msvc
SET SPACK_SYSTEM_DIRS=%PATH%
SET SPACK_RELOCATE_PATH=%CD%\tmp

nmake test