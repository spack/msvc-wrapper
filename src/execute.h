/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <iostream>
#include <string>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <vector>
#include <future>

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
    ExecuteCommand(std::string arg, StrList args);
    ExecuteCommand() = default;
    ExecuteCommand& operator=(ExecuteCommand &&ec);
    ~ExecuteCommand();
    bool Execute(const std::string &filename = empty);
    int Join();
private:
    void SetupExecute();
    bool ExecuteToolChainChild();
    int PipeChildToStdout();
    int PipeChildToStdErr();
    int CreateChildPipes();
    int CleanupHandles();
    int ReportExitCode();
    // Holds the exit code of the
    // pipe from child process stdout
    // to parent std out or file
    std::future<int> child_out_future;
    // Holds the exit code of the pipe
    // from child to parent stderr
    std::future<int> child_err_future;
    // Holds the exit code of the 
    // command wrapped by this class
    std::future<int> exit_code_future;
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
