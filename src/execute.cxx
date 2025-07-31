/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "execute.h"
#include <corecrt_wstring.h>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <handleapi.h>
#include <minwinbase.h>
#include <minwindef.h>
#include <namedpipeapi.h>
#include <processenv.h>
#include <processthreadsapi.h>
#include <winbase.h>
#include <winnt.h>

#include <cstdlib>
#include <future>
#include <iostream>
#include <string>
#include <utility>
#include "utils.h"

ExecuteCommand::ExecuteCommand(std::string command)
    : ChildStdOut_Rd(nullptr),
      ChildStdOut_Wd(nullptr),
      base_command(std::move(std::move(command))) {
    this->CreateChildPipes();
    this->SetupExecute();
}

ExecuteCommand::ExecuteCommand(std::string arg, const StrList& args)
    : ChildStdOut_Rd(nullptr),
      ChildStdOut_Wd(nullptr),
      base_command(std::move(std::move(arg))) {
    for (const auto& a : args) {
        this->command_args.push_back(a);
    }
    this->CreateChildPipes();
    this->SetupExecute();
}

ExecuteCommand& ExecuteCommand::operator=(ExecuteCommand&& ec) noexcept {
    this->ChildStdOut_Rd = std::move(ec.ChildStdOut_Rd);
    this->ChildStdOut_Wd = std::move(ec.ChildStdOut_Wd);
    this->procInfo = std::move(ec.procInfo);
    this->startInfo = std::move(ec.startInfo);
    this->saAttr = std::move(ec.saAttr);
    this->fileout = std::move(ec.fileout);
    this->write_to_file = std::move(ec.write_to_file);
    this->base_command = std::move(ec.base_command);
    this->command_args = std::move(ec.command_args);
    this->child_out_future = std::move(ec.child_out_future);
    this->exit_code_future = std::move(exit_code_future);
    return *this;
}

ExecuteCommand::~ExecuteCommand() {
    this->CleanupHandles();
}

void ExecuteCommand::SetupExecute() {
    PROCESS_INFORMATION pi_proc_info;
    STARTUPINFOW si_start_info;
    ZeroMemory(&pi_proc_info, sizeof(PROCESS_INFORMATION));

    // Set up members of the STARTUPINFO structure.
    // This structure specifies the STDIN and STDOUT handles for redirection.
    ZeroMemory(&si_start_info, sizeof(STARTUPINFOW));
    si_start_info.cb = sizeof(STARTUPINFOW);
    si_start_info.hStdError = this->ChildStdOut_Wd;
    si_start_info.hStdOutput = this->ChildStdOut_Wd;
    si_start_info.dwFlags |= STARTF_USESTDHANDLES;
    this->procInfo = pi_proc_info;
    this->startInfo = si_start_info;
}

/*
 * Create pipes and handles to communicate with
 * child process
 */
int ExecuteCommand::CreateChildPipes() {
    // Create stdout pipes
    SECURITY_ATTRIBUTES sa_attr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    sa_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_attr.bInheritHandle = TRUE;
    sa_attr.lpSecurityDescriptor = nullptr;
    this->saAttr = sa_attr;
    if (!CreatePipe(&this->ChildStdOut_Rd, &this->ChildStdOut_Wd, &sa_attr, 0))
        return 0;
    if (!SetHandleInformation(this->ChildStdOut_Rd, HANDLE_FLAG_INHERIT, 0))
        return 0;

    // create stderr pipes
    SECURITY_ATTRIBUTES sa_attr_err;
    // Set the bInheritHandle flag so pipe handles are inherited.
    sa_attr_err.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_attr_err.bInheritHandle = TRUE;
    sa_attr_err.lpSecurityDescriptor = nullptr;
    this->saAttrErr = sa_attr_err;
    if (!CreatePipe(&this->ChildStdErr_Rd, &this->ChildStdErr_Wd, &sa_attr_err,
                    0))
        return 0;
    if (!SetHandleInformation(this->ChildStdErr_Rd, HANDLE_FLAG_INHERIT, 0))
        return 0;

    return 1;
}

/*
 * Kick off subprocess executing a given toolchain, returns a value indicating
 * whether the subprocess was created successfully
 */
bool ExecuteCommand::ExecuteToolChainChild() {
    LPVOID lp_msg_buf;
    debug("Executing Command: " + this->ComposeCLI());
    const std::wstring c_command_line = ConvertAnsiToWide(this->ComposeCLI());
    wchar_t* nc_command_line = _wcsdup(c_command_line.c_str());
    if (!CreateProcessW(nullptr, nc_command_line, nullptr, nullptr, TRUE, 0,
                        nullptr, nullptr, &this->startInfo, &this->procInfo)) {
        // Handle errors coming from creation of child proc
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPTSTR>(&lp_msg_buf), 0, nullptr);
        std::cerr << "Failed to initiate child process from: "
                  << ConvertWideToANSI(nc_command_line) << " ";
        std::cerr << "With error: ";
        std::cerr << static_cast<char*>(lp_msg_buf) << "\n";
        free(nc_command_line);
        this->cpw_initalization_failure = true;
        return false;
    }
    // We've suceeded in kicking off the toolchain run
    // Explicitly close write handle to child proc stdout
    // as it is no longer needed and if we do not then cannot
    // determine when child proc is done
    free(nc_command_line);
    CloseHandle(this->ChildStdOut_Wd);
    return true;
}

/* 
 * Reads for the member variable holding a pipe to the wrapped processes'
 * STD_HANDLE (stdour or stderr) and writes either to this processes'
 * STD_HANDLE or a file, depending on how the process wrapper is configured
 */
int ExecuteCommand::PipeChildToStdStream(DWORD STD_HANDLE,
                                         HANDLE reader_handle) {
    DWORD dw_read;
    DWORD dw_written;
    CHAR ch_buf[BUFSIZE];
    BOOL b_success = TRUE;
    HANDLE h_parent_out;
    if (this->write_to_file && this->fileout != INVALID_HANDLE_VALUE) {
        h_parent_out = this->fileout;
    } else {
        h_parent_out = GetStdHandle(STD_HANDLE);
    }

    for (;;) {
        b_success = ReadFile(reader_handle, ch_buf, BUFSIZE, &dw_read, NULL);
        if (!b_success || (dw_read == 0 && this->terminated))
            break;
        if (dw_read != 0) {
            b_success =
                WriteFile(h_parent_out, ch_buf, dw_read, &dw_written, NULL);
            if (dw_written < dw_read && b_success) {
                // incomplete write but not a failure
                // since bSuccess is true
                // So lets write until bSuccess is false or
                // until all bytes are written
                int currentPos = dw_written;
                while ((dw_written < dw_read) || dw_written == 0) {
                    dw_read = dw_read - dw_written;
                    CHAR* partialBuf = new CHAR[dw_read];
                    for (int i = 0; i < dw_read; ++i) {
                        partialBuf[i] = ch_buf[currentPos + i];
                    }
                    b_success = WriteFile(h_parent_out, partialBuf, dw_read,
                                          &dw_written, NULL);
                    delete partialBuf;
                    if (!b_success)
                        break;
                    currentPos += dw_written;
                }
            }
            if (!b_success) {
                break;
            }
        }
        if (!b_success)
            break;
    }
    return static_cast<int>(static_cast<int>(b_success) == 0);
}

/*
 * Ensures handles and their underlying resources are
 * cleaned
 */
int ExecuteCommand::CleanupHandles() {
    if (!this->cpw_initalization_failure) {
        if (this->fileout != INVALID_HANDLE_VALUE)
            if (!SafeHandleCleanup(this->fileout))
                return 0;
        if (!SafeHandleCleanup(this->procInfo.hProcess))
            return 0;
        if (!SafeHandleCleanup(this->procInfo.hThread))
            return 0;
        return 1;
    }
    return 0;
}

/**
 * Reports the exit code of a given process, used as a callback to report
 * on the status of wrapped process which is performed asynchronously
 */
int ExecuteCommand::ReportExitCode() const {
    DWORD exit_code;
    while (GetExitCodeProcess(this->procInfo.hProcess, &exit_code)) {
        if (exit_code != STILL_ACTIVE)
            break;
    }
    this->terminated = true;
    CloseHandle(this->procInfo.hProcess);
    return exit_code;
}

std::string ExecuteCommand::ComposeCLI() {
    std::string cli;
    cli += this->base_command + " ";
    for (const auto& arg : this->command_args) {
        cli += arg + " ";
    }
    return cli;
}

/*
 * Execute the wrapped command in subprocess, creating the process, and
 * allowing it, and the piping of its stdout to this process to run asychronously
 * and storing the futures of each async operation to be waited on at a later point
 *
 * If this instance has been configured to write to a file instead of stdout, opens that file
 * and prepares it for writing
 *
 * Returns a value indicating whether or not the subprocess has been created sucessfully
*/
bool ExecuteCommand::Execute(const std::string& filename) {
    if (!filename.empty()) {
        this->write_to_file = true;
        this->fileout =
            CreateFileW(ConvertAnsiToWide(filename).c_str(), FILE_APPEND_DATA,
                        FILE_SHARE_WRITE | FILE_SHARE_READ, &this->saAttr,
                        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    bool const ret_code = this->ExecuteToolChainChild();
    if (ret_code) {
        this->child_out_future = std::async(
            std::launch::async, &ExecuteCommand::PipeChildToStdStream, this,
            STD_OUTPUT_HANDLE, this->ChildStdOut_Rd);
        this->child_err_future = std::async(
            std::launch::async, &ExecuteCommand::PipeChildToStdStream, this,
            STD_ERROR_HANDLE, this->ChildStdErr_Rd);
        this->exit_code_future = std::async(
            std::launch::async, &ExecuteCommand::ReportExitCode, this);
    }
    return ret_code;
}

/*
 * Blocks until the command initiated by execute terminates
 * and reports exit code of the process
 */
int ExecuteCommand::Join() {
    // Join primary thread first
    // This process sets the termianted flag
    // without which the reader threads will not
    // terminate, so the primary thread must be
    // joined first so we have a guaruntee that the
    // reader processes can exit
    int commandError = this->exit_code_future.get();
    if (!this->child_out_future.get())
        return -999;
    if (!this->child_err_future.get())
        return -999;
    return commandError;
}
