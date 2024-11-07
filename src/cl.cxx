/**
 * @file cl.cxx
 * @author John Parent (john.parent@kitware.com)
 * @brief A C++ wrapper file for the MSVC c and c++ compilers and linkers
 *        created for the Spack package manager.
 *
 *        This file implements the functionality required to inject Spack's build logic
 *        into the compiler/linker interface and drives the main entrypoint.
 * @date 2023-10-20
 *
 * @copyright  Copyright 2013-2023 Lawrence Livermore National Security, LLC and other
 *             Spack Project Developers. See the top-level COPYRIGHT file for details.
 *             SPDX-License-Identifier: (Apache-2.0 OR MIT)
 *
 */
#include "cl.h"
#include "utils.h"

#include <sstream>



std::string getSpackEnv(const char* env) {
    char* envVal = getenv(env);
    return envVal ? envVal : std::string();
}

std::string getSpackEnv(std::string env) {
    return getSpackEnv(env.c_str());
}

StrList getenvlist(std::string envVar, std::string delim = ";") {
    std::string envValue = getSpackEnv(envVar);
    if (! envValue.empty())
        return split(envValue, delim);
    else
        return StrList();
}

SpackEnvState SpackEnvState::loadSpackEnvState() {
    SpackEnvState spackenv = SpackEnvState();
    spackenv.Spack = getSpackEnv("SPACK");
    spackenv.SpackInstDir = getSpackEnv("SPACKINSTDIR");
    spackenv.SpackCC = getSpackEnv("SPACK_CC");
    spackenv.SpackCXX = getSpackEnv("SPACK_CXX");
    spackenv.SpackFC = getSpackEnv("SPACK_FC");
    spackenv.SpackF77 = getSpackEnv("SPACK_F77");
    spackenv.SpackRoot = getSpackEnv("SPACK_ROOT");
    spackenv.addDebugFlags = getSpackEnv("SPACK_ADD_DEBUG_FLAGS");
    spackenv.SpackFFlags = getenvlist("SPACK_FFLAGS", " ");
    spackenv.SpackCFlags = getenvlist("SPACK_CFLAGS", " ");
    spackenv.SpackCxxFlags = getenvlist("SPACK_CXXFLAGS", " ");
    spackenv.SpackLdFlags = getenvlist("SPACK_LDFLAGS", " ");
    spackenv.SpackLdLibs = getenvlist("SPACK_LDLIBS", " ");
    spackenv.SpackCompilerExtraRPaths = getenvlist("SPACK_COMPILER_EXTRA_RPATHS", "|");
    spackenv.SpackCompilerImplicitRPaths = getenvlist("SPACK_COMPILER_IMPLICIT_RPATHS", "|");
    spackenv.SpackIncludeDirs = getenvlist("SPACK_INCLUDE_DIRS", "|");
    spackenv.SpackLinkDirs = getenvlist("SPACK_LINK_DIRS", "|");
    spackenv.SpackCompilerFlagsKeep = getenvlist("SPACK_COMPILER_FLAGS_KEEP", "|");
    spackenv.SpackCompilerFlagsReplace = getenvlist("SPACK_COMPILER_FLAGS_REPLACE", "|");
    spackenv.SpackEnvPath = getenvlist("SPACK_ENV_PATH");
    spackenv.SpackCCRPathArg = getSpackEnv("SPACK_CC_RPATH_ARG");
    spackenv.SpackCXXRPathArg = getSpackEnv("SPACK_CXX_RPATH_ARG");
    spackenv.SpackFCRPathArg = getSpackEnv("SPACK_FC_RPATH_ARG");
    spackenv.SpackF77RPathArg = getSpackEnv("SPACK_F77_RPATH_ARG");
    spackenv.SpackSystemDirs = getenvlist("SPACK_SYSTEM_DIRS", "|");
    spackenv.SpackRPathDirs = getenvlist("SPACK_RPATH_DIRS", "|");
    spackenv.SpackLinkerArg = getSpackEnv("SPACK_LINKER_ARG");
    return spackenv;
}

char const* SpackException::what() {
    return this->message.c_str();
}

char const * SpackUnknownCompilerException::what() {
    std::string msg = "Unknown compiler" + this->message;
    return msg.c_str();
}

char const * SpackCompilerException::what() {
    std::string msg = "[spack cc] ERROR " + this->message;
    return msg.c_str();
}

char const * SpackCompilerContextException::what() {
    std::string msg = "Spack compiler must be run from Spack! Missing input: " + this->message;
    return msg.c_str();
}

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

void ClInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = spackenv.SpackCC;
}

void LdInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = std::string("link.exe");
}

void IntelFortranInvocation::loadToolchainDependentSpackVars(SpackEnvState &spackenv) {
    this->spackCommand = spackenv.SpackFC;
}


std::unique_ptr<ToolChainInvocation> ToolChainFactory::ParseToolChain(char const* const * argv) {
    std::string command(*argv);
    char const* const* cli(++argv);
    stripPathandExe(command);
    using lang = ToolChainFactory::Language;
    try {
        ToolChainFactory::Language language = SupportedTools.at(command);
        std::unique_ptr<ToolChainInvocation> Tool;
        if(language == lang::cpp) {
            Tool = std::unique_ptr<ClInvocation>(new ClInvocation(command, cli));
        }
        else if(language == lang::intelFortran) {
            Tool = std::unique_ptr<IntelFortranInvocation>(new IntelFortranInvocation(command, cli));
        }
        else {
            // If it's not c/c++ or fortran we're linking
            Tool = std::unique_ptr<LdInvocation>(new LdInvocation(command, cli));
        }
        return Tool;
    } catch (std::out_of_range& e) {
        throw SpackUnknownCompilerException(command);
    }
}

void ToolChainFactory::stripPathandExe(std::string &command) {
    stripPath(command);
    stripExe(command);
};

void ToolChainFactory::stripExe(std::string &command) {
    std::string::size_type loc = command.rfind(".exe");
    if ( std::string::npos != loc )
        command.erase(loc);
}

void ToolChainFactory::stripPath(std::string &command) {
    command.erase(0, command.find_last_of("\\/") + 1);
}

const std::map<std::string, ToolChainFactory::Language> ToolChainFactory::SupportedTools{
                                                        {"cl", ToolChainFactory::Language::cpp},
                                                        {"link", ToolChainFactory::Language::link},
                                                        {"ifort", ToolChainFactory::Language::intelFortran},
                                                        {"ifx", ToolChainFactory::Language::intelFortran}
                                                    };


void validate_spack_env() {
    std::vector<std::string> SpackEnv{
"SPACK_ENV_PATH"
"SPACK_DEBUG_LOG_DIR"
"SPACK_DEBUG_LOG_ID"
"SPACK_COMPILER_SPEC"
"SPACK_CC_RPATH_ARG"
"SPACK_CXX_RPATH_ARG"
"SPACK_F77_RPATH_ARG"
"SPACK_FC_RPATH_ARG"
"SPACK_LINKER_ARG"
"SPACK_SHORT_SPEC"
"SPACK_SYSTEM_DIRS"};
    for(auto &var: SpackEnv)
        if(!getenv(var.c_str())){
            throw SpackCompilerContextException(var + " isn't set in the environment and is expected to be");
        }
}

void die(std::string &cli ) {
    throw SpackCompilerException(cli);
}