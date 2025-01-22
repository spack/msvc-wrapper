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
    int CreateChildPipes();
    int CleanupHandles();
    int ReportExitCode();
    std::future<int> child_out_future;
    std::future<int> exit_code_future;
    std::string ComposeCLI();
    HANDLE ChildStdOut_Rd;
    HANDLE ChildStdOut_Wd;
    PROCESS_INFORMATION procInfo;
    STARTUPINFOW startInfo;
    SECURITY_ATTRIBUTES saAttr;
    HANDLE fileout = INVALID_HANDLE_VALUE;
    bool write_to_file;
    bool cpw_initalization_failure = false;
    std::string base_command;
    StrList command_args;
};
