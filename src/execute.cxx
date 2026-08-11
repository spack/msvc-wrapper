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
#include <processenv.h>
#include <processthreadsapi.h>
#include <synchapi.h>
#include <winbase.h>
#include <windows.h>  // NOLINT
#include <winnt.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include "utils.h"

enum : std::uint16_t { InvalidExitCode = 999 };

namespace {

/**
 * Produces an inheritable duplicate of one of this process' standard handles
 * so the child can be pointed at it via STARTUPINFOW.
 *
 * A missing source handle (a process started without a console and without
 * redirection) is not an error; the child simply gets no such handle.
 */
bool DuplicateInheritable(HANDLE source, HANDLE* out) {
    *out = INVALID_HANDLE_VALUE;
    if (source == nullptr || source == INVALID_HANDLE_VALUE) {
        return true;
    }
    HANDLE const self = GetCurrentProcess();
    return DuplicateHandle(self, source, self, out, 0, TRUE,
                           DUPLICATE_SAME_ACCESS) != 0;
}

}  // namespace

ExecuteCommand::ExecuteCommand(std::string command)
    : base_command(std::move(command)) {}

ExecuteCommand::ExecuteCommand(std::string arg, const StrList& args)
    : base_command(std::move(arg)), command_args(args) {}

ExecuteCommand& ExecuteCommand::operator=(
    ExecuteCommand&& execute_command) noexcept {
    if (this == &execute_command) {
        return *this;
    }
    this->CleanupHandles();
    this->procInfo = execute_command.procInfo;
    this->startInfo = execute_command.startInfo;
    this->fileout = execute_command.fileout;
    this->write_to_file = execute_command.write_to_file;
    this->cpw_initalization_failure = execute_command.cpw_initalization_failure;
    this->base_command = std::move(execute_command.base_command);
    this->command_args = std::move(execute_command.command_args);
    // Hand ownership over completely - the source must not close the handles
    // we just took when it is destroyed
    ZeroMemory(&execute_command.procInfo, sizeof(PROCESS_INFORMATION));
    execute_command.fileout = INVALID_HANDLE_VALUE;
    execute_command.write_to_file = false;
    return *this;
}

ExecuteCommand::~ExecuteCommand() {
    this->CleanupHandles();
}

/*
 * Kick off subprocess executing a given toolchain, returns a value indicating
 * whether the subprocess was created successfully
 *
 * The child is handed inheritable duplicates of our own standard handles, so
 * its output lands wherever ours does with no copying by this process. When
 * this instance was configured to write to a file, that file takes the place
 * of both stdout and stderr.
 */
bool ExecuteCommand::ExecuteToolChainChild() {
    const std::string cli = this->ComposeCLI();
    DEBUG_LOG("Executing Command: " + cli);
    std::wstring c_command_line;
    try {
        c_command_line = ConvertASCIIToWide(cli);
    } catch (const std::overflow_error& e) {
        std::cerr << e.what() << "\n";
        return false;
    }
    // Duplicate command line into writable buffer expected by CreateProcessW
    std::vector<wchar_t> cmdbuf(c_command_line.begin(), c_command_line.end());
    cmdbuf.push_back(L'\0');

    HANDLE const out_source = this->write_to_file
                                  ? this->fileout
                                  : GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE const err_source =
        this->write_to_file ? this->fileout : GetStdHandle(STD_ERROR_HANDLE);

    HANDLE inheritable_out = INVALID_HANDLE_VALUE;
    HANDLE inheritable_err = INVALID_HANDLE_VALUE;
    HANDLE inheritable_in = INVALID_HANDLE_VALUE;
    if (!DuplicateInheritable(out_source, &inheritable_out) ||
        !DuplicateInheritable(err_source, &inheritable_err) ||
        !DuplicateInheritable(GetStdHandle(STD_INPUT_HANDLE),
                              &inheritable_in)) {
        // Capture before anything else can overwrite the thread's last error
        const std::string dup_error = reportLastError();
        std::cerr << "Unable to prepare standard handles for child process: "
                  << dup_error << "\n";
        SafeHandleCleanup(inheritable_out);
        SafeHandleCleanup(inheritable_err);
        SafeHandleCleanup(inheritable_in);
        this->cpw_initalization_failure = true;
        return false;
    }

    this->startInfo.cb = sizeof(STARTUPINFOW);
    this->startInfo.dwFlags = STARTF_USESTDHANDLES;
    this->startInfo.hStdOutput = inheritable_out;
    this->startInfo.hStdError = inheritable_err;
    this->startInfo.hStdInput = inheritable_in;

    BOOL const created =
        CreateProcessW(nullptr, cmdbuf.data(), nullptr, nullptr, TRUE,
                       CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr,
                       &this->startInfo, &this->procInfo);
    // Capture this before the handle cleanup below overwrites it
    DWORD const spawn_error = created ? 0 : ::GetLastError();

    // The child has its own copies now; ours are dead weight either way
    SafeHandleCleanup(inheritable_out);
    SafeHandleCleanup(inheritable_err);
    SafeHandleCleanup(inheritable_in);
    this->startInfo.hStdOutput = INVALID_HANDLE_VALUE;
    this->startInfo.hStdError = INVALID_HANDLE_VALUE;
    this->startInfo.hStdInput = INVALID_HANDLE_VALUE;

    if (!created) {
        std::cerr << "Failed to initiate child process from: " << cli
                  << " With error: "
                  << std::system_category().message(
                         static_cast<int>(spawn_error))
                  << "\n";
        this->cpw_initalization_failure = true;
        return false;
    }
    return true;
}

/*
 * Ensures handles and their underlying resources are
 * cleaned
 */
int ExecuteCommand::CleanupHandles() {
    int result = 1;
    if (!SafeHandleCleanup(this->fileout))
        result = 0;
    if (!SafeHandleCleanup(this->procInfo.hProcess))
        result = 0;
    if (!SafeHandleCleanup(this->procInfo.hThread))
        result = 0;
    return result;
}

std::string ExecuteCommand::ComposeCLI() const {
    size_t reserved = this->base_command.size() + 3;
    for (const auto& arg : this->command_args) {
        reserved += arg.size() + 1;
    }
    std::string cli;
    cli.reserve(reserved);
    // CreateProcessW is called without an lpApplicationName, so the command
    // line itself has to identify the executable. An unquoted path containing
    // spaces makes Windows probe each prefix in turn (C:\Program.exe, ...)
    // before finding the real tool - a filesystem probe per invocation
    bool const needs_quoting =
        this->base_command.find_first_of(" \t") != std::string::npos &&
        this->base_command.front() != '\"';
    if (needs_quoting) {
        cli += '\"';
        cli += this->base_command;
        cli += '\"';
    } else {
        cli += this->base_command;
    }
    cli += ' ';
    for (const auto& arg : this->command_args) {
        cli += arg;
        cli += ' ';
    }
    return cli;
}

/*
 * Execute the wrapped command in a subprocess
 *
 * If this instance has been configured to write to a file instead of stdout,
 * opens that file and hands it to the child as its stdout and stderr
 *
 * Returns a value indicating whether or not the subprocess has been created
 * successfully
 */
bool ExecuteCommand::Execute(const std::string& filename) {
    if (!filename.empty()) {
        this->write_to_file = true;
        // The child needs to inherit this handle, so it is created
        // inheritable rather than being duplicated later
        SECURITY_ATTRIBUTES sa_attr;
        sa_attr.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa_attr.bInheritHandle = TRUE;
        sa_attr.lpSecurityDescriptor = nullptr;
        try {
            this->fileout = CreateFileW(
                ConvertASCIIToWide(filename).c_str(), FILE_APPEND_DATA,
                FILE_SHARE_WRITE | FILE_SHARE_READ, &sa_attr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
        } catch (const std::overflow_error& e) {
            std::cerr << e.what() << "\n";
            return false;
        }
        if (this->fileout == INVALID_HANDLE_VALUE) {
            const std::string open_error = reportLastError();
            std::cerr << "Unable to open " << filename
                      << " to capture command output: " << open_error << "\n";
            return false;
        }
    }
    return this->ExecuteToolChainChild();
}

/*
 * Blocks until the command initiated by execute terminates
 * and reports exit code of the process
 */
DWORD ExecuteCommand::Join() {
    if (this->procInfo.hProcess == nullptr ||
        this->procInfo.hProcess == INVALID_HANDLE_VALUE) {
        // Nothing was spawned (or this has already been joined); the spawn
        // failure has already been reported by ExecuteToolChainChild
        return InvalidExitCode;
    }
    if (WaitForSingleObject(this->procInfo.hProcess, INFINITE) !=
        WAIT_OBJECT_0) {
        const std::string wait_error = reportLastError();
        std::cerr << "Failed waiting on child process: " << wait_error << "\n";
        return InvalidExitCode;
    }
    DWORD exit_code = InvalidExitCode;
    if (!GetExitCodeProcess(this->procInfo.hProcess, &exit_code)) {
        const std::string code_error = reportLastError();
        std::cerr << "Unable to retrieve child process exit code: "
                  << code_error << "\n";
        return InvalidExitCode;
    }
    // Release the process, and any captured output file, now that the child is
    // gone - callers rename and delete those files immediately after joining
    this->CleanupHandles();
    return exit_code;
}
