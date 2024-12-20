#include "execute.h"

#include <sstream>

ExecuteCommand::ExecuteCommand(std::string command) :
    ChildStdOut_Rd(NULL),
    ChildStdOut_Wd(NULL),
    baseCommand(command)
{
    this->createChildPipes();
    this->setupExecute();
}

ExecuteCommand::ExecuteCommand(std::string arg, StrList args) :
    ChildStdOut_Rd(NULL),
    ChildStdOut_Wd(NULL),
    baseCommand(arg)
{
    for(const auto a: args) {
        this->commandArgs.push_back(a);
    }
    this->createChildPipes();
    this->setupExecute();
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
    this->baseCommand = std::move(ec.baseCommand);
    this->commandArgs = std::move(ec.commandArgs);
    this->child_out_future = std::move(ec.child_out_future);
    this->exit_code_future = std::move(exit_code_future);
    return *this;
}

ExecuteCommand::~ExecuteCommand()
{
    this->cleanupHandles();
}

void ExecuteCommand::setupExecute()
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
int ExecuteCommand::createChildPipes()
{
    SECURITY_ATTRIBUTES saAttr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    this->saAttr = saAttr;
    if( !CreatePipe(&this->ChildStdOut_Rd, &this->ChildStdOut_Wd, &saAttr, 0) )
        return 0;
    if ( !SetHandleInformation(ChildStdOut_Rd, HANDLE_FLAG_INHERIT, 0) )
        return 0;
    return 1;
}

/*
 * Kick off subprocess executing a given toolchain
 */
int ExecuteCommand::executeToolChainChild()
{
    LPVOID lpMsgBuf;
    const std::wstring c_commandLine = ConvertAnsiToWide(this->composeCLI());
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
        std::cerr << (char*)lpMsgBuf << "\n";
        free(nc_commandLine);
        return 0;
    }
    // We've suceeded in kicking off the toolchain run
    // Explicitly close write handle to child proc stdout
    // as it is no longer needed and if we do not then cannot
    // determine when child proc is done
    free(nc_commandLine);
    CloseHandle(this->ChildStdOut_Wd);
    return 1;
}

/* 
 * Execute the command and then after it finishes collect all of 
 * its output.
 */
int ExecuteCommand::pipeChildToStdout()
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = TRUE;
    HANDLE hParentOut;
    if (this->write_to_file) {
        hParentOut = this->fileout;
    }
    else {
        hParentOut = GetStdHandle(STD_OUTPUT_HANDLE);
    }

    for (;;)
    {
        bSuccess = ReadFile( this->ChildStdOut_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break;

        bSuccess = WriteFile(hParentOut, chBuf,
                            dwRead, &dwWritten, NULL);
        if (! bSuccess ) break;
    }
    return !bSuccess;
}

/*
 * Ensures handles and their underlying resources are
 * cleaned
 */
int ExecuteCommand::cleanupHandles()
{

    if(this->fileout != INVALID_HANDLE_VALUE)
        if(!safeHandleCleanup(this->fileout))
            return 0;
    if(!safeHandleCleanup(this->procInfo.hProcess) 
        || !safeHandleCleanup(this->procInfo.hThread))
        return 0;
    return 1;
}

int ExecuteCommand::reportExitCode()
{
    DWORD exit_code;
    while(GetExitCodeProcess(this->procInfo.hProcess, &exit_code)) {
        if(exit_code != STILL_ACTIVE)
            break;
    }
    return exit_code;
}

std::string ExecuteCommand::composeCLI()
{
    std::string CLI;
    CLI += this->baseCommand + " ";
    for(auto arg: this->commandArgs){
        CLI += arg + " ";
    }
    return CLI;
}

/*
 * Execute command in subprocess, piping stdout to parent
 * and returning the exit code of the subprocess
*/
int ExecuteCommand::execute(const std::string &filename)
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
    int ret_code = this->executeToolChainChild();
    this->child_out_future = std::async(std::launch::async, &ExecuteCommand::pipeChildToStdout, this);
    this->exit_code_future = std::async(std::launch::async, &ExecuteCommand::reportExitCode, this);
    return ret_code;
}

/*
 * Blocks until the command initiated by execute terminates
 * and reports exit code
 */
int ExecuteCommand::join()
{
    if(!this->child_out_future.get())
        return -999;
    return this->exit_code_future.get();
}
