/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>
#include <string>
#include <vector>

#include "utils.h"

const std::string empty = std::string();

/**
 * @brief Spawns a wrapped toolchain process and reports its exit code
 *
 * The wrapper is invoked once per compiled source file, so this class does as
 * little as possible per invocation: the child inherits this process' standard
 * handles directly rather than having its output pumped through a pipe, and
 * the parent blocks on the child rather than polling it.
 *
 * When Execute() is given a filename, the child's stdout and stderr are
 * pointed at that file instead. That is used by the relocation path to capture
 * dumpbin's export listing; nothing on the compile or link path needs it.
 *
 * */
class ExecuteCommand {
   public:
    // constructor for single executable/arguments + command in one string
    explicit ExecuteCommand(std::string command);
    ExecuteCommand(std::string arg, const StrList& args);
    ExecuteCommand() = default;
    ExecuteCommand(const ExecuteCommand&) = delete;
    ExecuteCommand& operator=(const ExecuteCommand&) = delete;
    ExecuteCommand& operator=(ExecuteCommand&& execute_command) noexcept;
    ~ExecuteCommand();
    bool Execute(const std::string& filename = empty);
    DWORD Join();
    int CleanupHandles();

   private:
    bool ExecuteToolChainChild();
    std::string ComposeCLI() const;

    PROCESS_INFORMATION procInfo{};
    STARTUPINFOW startInfo{};
    // Destination for the child's stdout/stderr when Execute() was given a
    // filename; INVALID_HANDLE_VALUE means "inherit ours"
    HANDLE fileout = INVALID_HANDLE_VALUE;
    bool write_to_file = false;
    bool cpw_initalization_failure = false;
    std::string base_command;
    StrList command_args;
};
