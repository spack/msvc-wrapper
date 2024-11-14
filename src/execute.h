#pragma once

#include <iostream>
#include <string>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>
#include <vector>

#define BUFSIZE 4096

const std::string empty = std::string();

class ExecuteCommand {
public:
    // constructor for single executable/arguments + command in one string
    ExecuteCommand(std::string command);
    // constructor for command + arguments
    template<typename... Arguments>
    ExecuteCommand(std::string arg, Arguments... args);
    ExecuteCommand(std::string arg, StrList args);
    ExecuteCommand() = default;
    ~ExecuteCommand();
    void execute(const std::string &filename = empty);
private:
    void setupExecute();
    void executeToolChainChild();
    bool pipeChildToStdout();
    void createChildPipes();
    void cleanupHandles();
    void safeHandleCleanup(HANDLE &handle);
    std::string composeCLI();
    HANDLE ChildStdOut_Rd;
    HANDLE ChildStdOut_Wd;
    PROCESS_INFORMATION procInfo;
    STARTUPINFOW startInfo;
    SECURITY_ATTRIBUTES saAttr;
    HANDLE fileout;
    bool write_to_file;
    std::string baseCommand;
    std::vector<std::string> commandArgs;
};
