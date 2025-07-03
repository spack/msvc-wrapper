/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include "execute.h"

#include <sstream>

ExecuteCommand::ExecuteCommand(std::string command) :
    ChildStdOut_Rd(NULL),
    ChildStdOut_Wd(NULL),
    base_command(command)
{
    this->CreateChildPipes();
    this->SetupExecute();
}

ExecuteCommand::ExecuteCommand(std::string arg, StrList args) :
    ChildStdOut_Rd(NULL),
    ChildStdOut_Wd(NULL),
    base_command(arg)
{
    for(const auto a: args) {
        this->command_args.push_back(a);
    }
    this->CreateChildPipes();
    this->SetupExecute();
}

ExecuteCommand& ExecuteCommand::operator=(ExecuteCommand &&ec)
{
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

ExecuteCommand::~ExecuteCommand()
{
    this->CleanupHandles();
}

void ExecuteCommand::SetupExecute()
{
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOW siStartInfo;
    ZeroMemory( &piProcInfo, sizeof(PROCESS_INFORMATION) );

    // Set up members of the STARTUPINFO structure.
    // This structure specifies the STDIN and STDOUT handles for redirection.
    ZeroMemory( &siStartInfo, sizeof(STARTUPINFOW) );
    siStartInfo.cb = sizeof(STARTUPINFOW);
    siStartInfo.hStdError = this->ChildStdOut_Wd;
    siStartInfo.hStdOutput = this->ChildStdOut_Wd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
    this->procInfo = piProcInfo;
    this->startInfo = siStartInfo;
}

/*
 * Create pipes and handles to communicate with
 * child process
 */
int ExecuteCommand::CreateChildPipes()
{
    // Create stdout pipes
    SECURITY_ATTRIBUTES saAttr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    this->saAttr = saAttr;
    if( !CreatePipe(&this->ChildStdOut_Rd, &this->ChildStdOut_Wd, &saAttr, 0) )
        return 0;
    if ( !SetHandleInformation(this->ChildStdOut_Rd, HANDLE_FLAG_INHERIT, 0) )
        return 0;

    // create stderr pipes
    SECURITY_ATTRIBUTES saAttrErr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttrErr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttrErr.bInheritHandle = TRUE;
    saAttrErr.lpSecurityDescriptor = NULL;
    this->saAttrErr = saAttrErr;
    if( !CreatePipe(&this->ChildStdErr_Rd, &this->ChildStdErr_Wd, &saAttrErr, 0) )
        return 0;
    if ( !SetHandleInformation(this->ChildStdErr_Rd, HANDLE_FLAG_INHERIT, 0) )
        return 0;

    return 1;
}

/*
 * Kick off subprocess executing a given toolchain, returns a value indicating
 * whether the subprocess was created successfully
 */
bool ExecuteCommand::ExecuteToolChainChild()
{
    LPVOID lpMsgBuf;
    debug("Executing Command: " + this->ComposeCLI());
    const std::wstring c_commandLine = ConvertAnsiToWide(this->ComposeCLI());
    wchar_t * nc_commandLine = _wcsdup(c_commandLine.c_str());
    if(! CreateProcessW(
        NULL,
        nc_commandLine,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &this->startInfo,
        &this->procInfo)
    )
    {
        // Handle errors coming from creation of child proc
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL
        );
        std::cerr << "Failed to initiate child process from: " << ConvertWideToANSI(nc_commandLine) << " ";
        std::cerr << "With error: ";
        std::cerr << (char*)lpMsgBuf << "\n";
        free(nc_commandLine);
        this->cpw_initalization_failure = true;
        return false;
    }
    // We've suceeded in kicking off the toolchain run
    // Explicitly close write handle to child proc stdout
    // as it is no longer needed and if we do not then cannot
    // determine when child proc is done
    free(nc_commandLine);
    CloseHandle(this->ChildStdOut_Wd);
    return true;
}


/* 
 * Reads for the member variable holding a pipe to the wrapped processes'
 * STDERR and writes either to this processes' STDERR or a file, depending on
 * how the process wrapper is configured
 */
int ExecuteCommand::PipeChildToStdErr()
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = TRUE;
    HANDLE hParentOut;
    if (this->write_to_file && this->fileout != INVALID_HANDLE_VALUE) {
        hParentOut = this->fileout;
    }
    else {
        hParentOut = GetStdHandle(STD_ERROR_HANDLE);
    }

    for (;;)
    {
        bSuccess = ReadFile( this->ChildStdErr_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || (dwRead == 0 && this->terminated) ) break;
        if(dwRead != 0) {
            bSuccess = WriteFile(hParentOut, chBuf,
                                dwRead, &dwWritten, NULL);
            if (dwWritten < dwRead && bSuccess){
                // incomplete write but not a failure
                // since bSuccess is true
                // So lets write until bSuccess is false or
                // until all bytes are written
                int currentPos = dwWritten;
                while((dwWritten < dwRead) || dwWritten == 0) {
                    dwRead = dwRead - dwWritten;
                    CHAR * partialBuf = new CHAR[dwRead];
                    for(int i = 0; i < dwRead; ++i) {
                        partialBuf[i] = chBuf[currentPos + i];
                    }
                    bSuccess = WriteFile(hParentOut, partialBuf,
                                        dwRead, &dwWritten, NULL);
                    if (! bSuccess) break;
                    currentPos += dwWritten;
                }
            }
            if (! bSuccess ) {
                break;
            }
        }
        if (! bSuccess ) break;
    }
    return !bSuccess;
}


/* 
 * Reads for the member variable holding a pipe to the wrapped processes'
 * STDOUT and writes either to this processes' STDOUT or a file, depending on
 * how the process wrapper is configured
 */
int ExecuteCommand::PipeChildToStdout()
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = TRUE;
    HANDLE hParentOut;
    if (this->write_to_file && this->fileout != INVALID_HANDLE_VALUE) {
        hParentOut = this->fileout;
    }
    else {
        hParentOut = GetStdHandle(STD_OUTPUT_HANDLE);
    }

    for (;;)
    {
        bSuccess = ReadFile( this->ChildStdOut_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        // Typically dwRead == 0 indicates the writer end of the pipe has ceased writing
        // however if the writer were to invoke WriteFile with a size of 0, dwRead would
        // be 0 but the writer would not have terminated. 
        // As such we need an explicit indication the writer process has termianted.
        // From the MSVC docs:
        // If the lpNumberOfBytesRead parameter is zero when ReadFile returns TRUE on a pipe,
        // the other end of the pipe called the WriteFile function with nNumberOfBytesToWrite 
        // set to zero.
        if( ! bSuccess || (dwRead == 0 && this->terminated) ) break;
        if(dwRead != 0){
            bSuccess = WriteFile(hParentOut, chBuf,
                                dwRead, &dwWritten, NULL);
            if (dwWritten < dwRead && bSuccess){
                // incomplete write but not a failure
                // since bSuccess is true
                // So lets write until bSuccess is false or
                // until all bytes are written
                int currentPos = dwWritten;
                while((dwWritten < dwRead) || dwWritten == 0) {
                    dwRead = dwRead - dwWritten;
                    CHAR * partialBuf = new CHAR[dwRead];
                    for(int i = 0; i < dwRead; ++i) {
                        partialBuf[i] = chBuf[currentPos + i];
                    }
                    bSuccess = WriteFile(hParentOut, partialBuf,
                                        dwRead, &dwWritten, NULL);
                    if (! bSuccess) break;
                    currentPos += dwWritten;
                }
            }
            if (! bSuccess ) {
                break;
            }
        }
        if (! bSuccess ) break;
    }
    return !bSuccess;
}

/*
 * Ensures handles and their underlying resources are
 * cleaned
 */
int ExecuteCommand::CleanupHandles()
{
    if(!this->cpw_initalization_failure) {
        if(this->fileout != INVALID_HANDLE_VALUE)
            if(!SafeHandleCleanup(this->fileout))
                return 0;
        if(!SafeHandleCleanup(this->procInfo.hProcess))
            return 0;
        if( !SafeHandleCleanup(this->procInfo.hThread))
            return 0;
        return 1;
    }
    return 0;

}

/**
 * Reports the exit code of a given process, used as a callback to report
 * on the status of wrapped process which is performed asynchronously
 */
int ExecuteCommand::ReportExitCode()
{
    DWORD exit_code;
    while(GetExitCodeProcess( this->procInfo.hProcess, &exit_code )) {
        if(exit_code != STILL_ACTIVE)
            break;
    }
    this->terminated = true;
    CloseHandle(this->procInfo.hProcess);
    return exit_code;
}

std::string ExecuteCommand::ComposeCLI()
{
    std::string CLI;
    CLI += this->base_command + " ";
    for(auto arg: this->command_args){
        CLI += arg + " ";
    }
    return CLI;
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
bool ExecuteCommand::Execute(const std::string &filename)
{
    if (!filename.empty()){
        this->write_to_file = true;
        this->fileout = CreateFileW(ConvertAnsiToWide(filename).c_str(),
                                    FILE_APPEND_DATA,
                                    FILE_SHARE_WRITE | FILE_SHARE_READ,
                                    &this->saAttr,
                                    OPEN_ALWAYS,
                                    FILE_ATTRIBUTE_NORMAL,
                                    NULL
                                    );
    }
    bool ret_code = this->ExecuteToolChainChild();
    if (ret_code) {
        this->child_out_future = std::async(std::launch::async, &ExecuteCommand::PipeChildToStdout, this);
        this->child_err_future = std::async(std::launch::async, &ExecuteCommand::PipeChildToStdErr, this);
        this->exit_code_future = std::async(std::launch::async, &ExecuteCommand::ReportExitCode, this);
    }
    return ret_code;
}

/*
 * Blocks until the command initiated by execute terminates
 * and reports exit code of the process
 */
int ExecuteCommand::Join()
{
    // Allow primary command to conclude
    // ensures stdout and stderr readers
    // exit only once primary command process
    // has concluded
    int commandError = this->exit_code_future.get();
    if(!this->child_out_future.get())
        return -999;
    if(!this->child_err_future.get())
        return -999;
    return commandError;
}
