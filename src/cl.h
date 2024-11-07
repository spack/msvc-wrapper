/**
 * @file cl.hxx
 * @author John Parent (john.parent@kitware.com)
 * @brief A C++ wrapper header file for the MSVC c and c++ compilers and linkers
 *        created for the Spack package manager.
 *        Eclipses the names cl.exe and link.exe in the PATH during Spackc runtime,
 *        intercepting calls to the compiler/linker and injecting Spack specific logic
 *        and flags into the compiler and link interfaces for MSVC driven compilation
 *
 *        This header files specificies the interface with which the compiler
 *        wrapper interacts with the Spack build env, and the associated calls to
 *        the compiler and linker
 * @date 2023-10-20
 * @copyright  Copyright 2013-2023 Lawrence Livermore National Security, LLC and other
 *             Spack Project Developers. See the top-level COPYRIGHT file for details.
 *             SPDX-License-Identifier: (Apache-2.0 OR MIT)
 *
 */


#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

#include "version.hxx"

#define BUFSIZE 4096

struct SpackEnvState{
    std::string addDebugFlags;
    StrList SpackFFlags;
    StrList SpackCFlags;
    StrList SpackCxxFlags;
    StrList SpackLdFlags;
    StrList SpackLdLibs;
    StrList SpackCompilerExtraRPaths;
    StrList SpackCompilerImplicitRPaths;
    StrList SpackIncludeDirs;
    StrList SpackLinkDirs;
    StrList SpackCompilerFlagsKeep;
    StrList SpackCompilerFlagsReplace;
    StrList SpackEnvPath;
    StrList SpackSystemDirs;
    StrList SpackRPathDirs;
    std::string SpackCCRPathArg;
    std::string SpackCXXRPathArg;
    std::string SpackFCRPathArg;
    std::string SpackF77RPathArg;
    std::string SpackLinkerArg;
    std::string Spack;
    std::string SpackInstDir;
    std::string SpackCC;
    std::string SpackCXX;
    std::string SpackFC;
    std::string SpackF77;
    std::string SpackRoot;

    static SpackEnvState loadSpackEnvState();
};

class SpackException : public std::exception {
public:
    SpackException(std::string msg) : message(msg) {}
    char const* what();
protected:
    std::string message;
};

class SpackUnknownCompilerException : public SpackException {
    using SpackException::SpackException;
public:
    char const * what();
};

class SpackCompilerException : public SpackException {
    using SpackException::SpackException;
public:
    char const * what();
};

class SpackCompilerContextException : public SpackException {
    using SpackException::SpackException;
public:
    char const * what();
};

class ToolChainInvocation{
public:
    ToolChainInvocation(std::string command, char const* const* cli);
    virtual ~ToolChainInvocation();
    virtual void interpolateSpackEnv(SpackEnvState &spackenv);
    virtual void invokeToolchain();
protected:
    virtual void parse_command_args(char const* const* cli);
    virtual void setupExecute();
    bool pipeChildtoStdOut();
    virtual void loadToolchainDependentSpackVars(SpackEnvState &spackenv) = 0;
    virtual void executeToolChainChild();
    virtual void createChildPipes();
    std::string composeIncludeArg(std::string &include);
    std::string composeLibPathArg(std::string &libPath);
    void addExtraLibPaths(StrList paths);
    std::string composeCLI();
    virtual void cleanupHandles();
    virtual void safeHandleCleanup(HANDLE &handle);

    std::string command;
    std::string lang;
    StrList CommandArgs;
    StrList includeArgs;
    StrList libDirArgs;
    StrList libArgs;
    HANDLE ChildStdOut_Rd;
    HANDLE ChildStdOut_Wd;
    PROCESS_INFORMATION procInfo;
    STARTUPINFOW startInfo;
    std::string spackCommand;
};

/**
 * @brief ClInvocation exposes an interface driving invocations of
 * cl.exe and defines the parameters of the call to said executable
 */
class ClInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
private:
    void loadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "c/c++";
};

/**
 * @brief ClInvocation exposes an interface driving invocations of
 * link.exe and defines the parameters of the call to said executable
 */
class LdInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
private:
    void loadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "link";
};

/**
 * @brief ClInvocation exposes an interface driving invocations of
 * ifx.exe and defines the parameters of the call to said executable
 */
class IntelFortranInvocation : public ToolChainInvocation {
public:
    using ToolChainInvocation::ToolChainInvocation;
private:
    void loadToolchainDependentSpackVars(SpackEnvState &spackenv);
    std::string lang = "intel fortran";
};

class ToolChainFactory{
public:
    static std::unique_ptr<ToolChainInvocation> ParseToolChain(char const* const * argv);
private:
    static void stripPathandExe(std::string &command);
    static void stripExe(std::string &command);
    static void stripPath(std::string &command);
    enum Language {
        cpp,
        intelFortran,
        link
    };
    const static std::map<std::string, Language> SupportedTools;

};
