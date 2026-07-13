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
#include <future>
#include <iostream>
#include <string>
#include <vector>

#include "utils.h"

#define BUFSIZE 4096

const std::string empty = std::string();

/**
 * @brief
 */
class ExecuteCommand {
   public:
    // constructor for single executable/arguments + command in one string
    ExecuteCommand(std::string command);
    ExecuteCommand(std::string arg, const StrList& args);
    ExecuteCommand() = default;
    ExecuteCommand& operator=(ExecuteCommand&& execute_command) noexcept;
    ~ExecuteCommand();
    bool Execute(const std::string& filename = empty);
    DWORD Join();
    // Idempotent - safe to call before destruction to release resources
    // (e.g. an output file handle) earlier than the object's lifetime would
    // otherwise allow; the destructor calls this again harmlessly.
    int CleanupHandles();

   private:
    void SetupExecute();
    bool ExecuteToolChainChild();
    int PipeChildToStdStream(DWORD STD_HANDLE, HANDLE reader_handle);
    int CreateChildPipes();
    DWORD ReportExitCode();
    // Holds the exit code of the
    // pipe from child process stdout
    // to parent std out or file
    std::future<int> child_out_future;
    // Holds the exit code of the pipe
    // from child to parent stderr
    std::future<int> child_err_future;
    // Holds the exit code of the
    // command wrapped by this class
    std::future<DWORD> exit_code_future;
    std::string ComposeCLI();
    HANDLE ChildStdOut_Rd;
    HANDLE ChildStdOut_Wd;
    HANDLE ChildStdErr_Rd;
    HANDLE ChildStdErr_Wd;
    PROCESS_INFORMATION procInfo;
    STARTUPINFOW startInfo;
    SECURITY_ATTRIBUTES saAttr;
    SECURITY_ATTRIBUTES saAttrErr;
    HANDLE fileout = INVALID_HANDLE_VALUE;
    bool write_to_file = false;
    bool cpw_initalization_failure = false;
    bool terminated = false;
    std::string base_command;
    StrList command_args;
};
