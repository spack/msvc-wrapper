#include "execute.h"
#include "utils.h"

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

void ExecuteCommand::createChildPipes()
{
    SECURITY_ATTRIBUTES saAttr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    this->saAttr = saAttr;
    if( !CreatePipe(&this->ChildStdOut_Rd, &this->ChildStdOut_Wd, &saAttr, 0) )
        throw SpackException("Could not create Child Pipe");
    if ( !SetHandleInformation(ChildStdOut_Rd, HANDLE_FLAG_INHERIT, 0) )
        throw SpackException("Child pipe handle inappropriately inhereited");
}

void ExecuteCommand::executeToolChainChild()
{
    LPVOID lpMsgBuf;
    wchar_t * commandLine = &ConvertAnsiToWide(this->composeCLI())[0];
    if(! CreateProcessW(
        NULL,
        commandLine,
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
        // Handle errors coming from creating of child proc
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
        throw SpackException((char *)lpMsgBuf);
    }
    // We've suceeded in kicking off the toolchain run
    // Explicitly close write handle to child proc stdout
    // as it is no longer needed and if we do not then cannot
    // determine when child proc is done
    CloseHandle(this->ChildStdOut_Wd);
}

bool ExecuteCommand::pipeChildToStdout()
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
    return bSuccess;
}

void ExecuteCommand::cleanupHandles()
{
    try {
        this->safeHandleCleanup(this->procInfo.hProcess);
        this->safeHandleCleanup(this->procInfo.hThread);
    }
    catch(SpackException &e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

}

void ExecuteCommand::safeHandleCleanup(HANDLE &handle)
{
    if(handle){
        if ( !CloseHandle(handle) ) {
            std::stringstream os_error;
            os_error << GetLastError();
            throw SpackException(os_error.str());
        }
    }
}

std::string ExecuteCommand::composeCLI()
{
    std::string CLI;
    CLI += this->baseCommand + " ";
    auto addToCLI = [&](StrList args){
        for( auto& arg: args ){
            CLI += arg + " ";
        }
    };
    addToCLI(this->commandArgs);

    return CLI;
}

void ExecuteCommand::execute(const std::string &filename)
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
    try {
        this->executeToolChainChild();
        this->pipeChildToStdout();
    }
    catch(SpackException &e) {
        std::cerr << "exception: " << e.what() << "\n";
        throw SpackException("Failed execution");
    }

}