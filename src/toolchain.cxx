#include "toolchain.h"

#include <sstream>

ToolChainInvocation::ToolChainInvocation(std::string command, char const* const* cli) : ChildStdOut_Rd(NULL),
                                                                    ChildStdOut_Wd(NULL),
                                                                    includeArgs(StrList()),
                                                                    libArgs(StrList()),
                                                                    CommandArgs(StrList()),
                                                                    libDirArgs(StrList())
{
    this->command = command;
    this->parse_command_args(cli);
}

ToolChainInvocation::~ToolChainInvocation() {
    this->cleanupHandles();
}

void ToolChainInvocation::interpolateSpackEnv(SpackEnvState &spackenv) {
    // inject Spack includes before the default includes
    for( auto &include: spackenv.SpackIncludeDirs )
    {
        auto incArg = this->composeIncludeArg(include);
        this->includeArgs.insert(this->includeArgs.begin(), incArg);
    }
    for( auto &lib: spackenv.SpackLdLibs )
    {
        this->libArgs.push_back(lib);
    }
    this->addExtraLibPaths(spackenv.SpackLinkDirs);
    this->addExtraLibPaths(spackenv.SpackRPathDirs);
    this->addExtraLibPaths(spackenv.SpackCompilerExtraRPaths);
    this->addExtraLibPaths(spackenv.SpackCompilerImplicitRPaths);
    this->loadToolchainDependentSpackVars(spackenv);
}

void ToolChainInvocation::invokeToolchain() {
    this->setupExecute();
    this->executeToolChainChild();
    this->pipeChildtoStdOut();
}

void ToolChainInvocation::parse_command_args(char const* const* cli) {
    // Collect include args as we need to ensure Spack
    // Includes come first
    for( char const* const* c = cli; *c; c++ ){
        std::string arg = std::string(*c);
        if ( startswith(arg, "/I") )
            // We have an include arg
            // can have an optional space
            // check if there are characters after
            // "/I" and if not we consider the next
            // argument to be the include
            if (arg.size() > 2)
                this->includeArgs.push_back(arg);
            else
                this->includeArgs.push_back(std::string(*(++c)));
        else if( endswith(arg, ".lib") )
            // Lib args are just libraries
            // provided like system32.lib on the
            // command line.
            // lib specification order does not matter
            // on MSVC but this is useful for filtering system libs
            // and adding all libs
            this->libArgs.push_back(arg);
        else
            this->CommandArgs.push_back(arg);
    }
}

void ToolChainInvocation::setupExecute() {
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
    this->startInfo= siStartInfo;
}

bool ToolChainInvocation::pipeChildtoStdOut() {
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = TRUE;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    for (;;)
    {
        bSuccess = ReadFile( this->ChildStdOut_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if( ! bSuccess || dwRead == 0 ) break;

        bSuccess = WriteFile(hParentStdOut, chBuf,
                            dwRead, &dwWritten, NULL);
        if (! bSuccess ) break;
    }
    return bSuccess;
}

void ToolChainInvocation::executeToolChainChild() {
    LPVOID lpMsgBuf;
    wchar_t * commandLine = &ConvertAnsiToWide(this->composeCLI())[0];
    if(! CreateProcessW(
        ConvertAnsiToWide(this->spackCommand).c_str(),
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
    // We've suceeded in kicking off the toolchain run
    // Explicitly close write handle to child proc stdout
    // as it is no longer needed and if we do not then cannot
    // determine when child proc is done
    CloseHandle(this->ChildStdOut_Wd);
}

void ToolChainInvocation::createChildPipes() {
    SECURITY_ATTRIBUTES saAttr;
    // Set the bInheritHandle flag so pipe handles are inherited.
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if( !CreatePipe(&this->ChildStdOut_Rd, &this->ChildStdOut_Wd, &saAttr, 0) )
        throw SpackException("Could not create Child Pipe");
    if ( !SetHandleInformation(ChildStdOut_Rd, HANDLE_FLAG_INHERIT, 0) )
        throw SpackException("Child pipe handle inappropriately inhereited");
}

std::string ToolChainInvocation::composeIncludeArg(std::string &include) {
    return "/I" + include;
}

std::string ToolChainInvocation::composeLibPathArg(std::string &libPath) {
    return "/LIBPATH:" + libPath;
}

void ToolChainInvocation::addExtraLibPaths(StrList paths) {
    for( auto &libDir: paths )
    {
        this->libDirArgs.push_back(this->composeLibPathArg(libDir));
    }
}

std::string ToolChainInvocation::composeCLI() {
    std::string SpackCompilerCLI;
    auto addToCLI = [&](StrList args){
        for( auto& arg: args ){
            SpackCompilerCLI += arg + " ";
        }
    };
    addToCLI(this->CommandArgs);
    addToCLI(this->includeArgs);
    addToCLI(this->libDirArgs);
    addToCLI(this->libArgs);
    return SpackCompilerCLI;
}

void ToolChainInvocation::cleanupHandles() {

    this->safeHandleCleanup(this->procInfo.hProcess);
    this->safeHandleCleanup(this->procInfo.hThread);
}

void ToolChainInvocation::safeHandleCleanup(HANDLE &handle) {
    if ( !CloseHandle(handle) ) {
        std::stringstream os_error;
        os_error << GetLastError();
        throw SpackException(os_error.str());
    }
}
