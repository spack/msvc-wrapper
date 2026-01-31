/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <string>

#include "utils.h"

class LinkerInvocation {
   public:
    explicit LinkerInvocation(std::string linkLine);
    explicit LinkerInvocation(const StrList& linkline);
    ~LinkerInvocation() = default;
    void Parse();
    bool IsExeLink() const;
    std::string get_out() const;
    std::string get_mangled_out() const;
    std::string get_implib_name() const;
    std::string get_def_file() const;
    StrList get_rsp_files() const;
    StrList get_rc_files() const;
    StrList get_input_files() const;
    std::string get_lib_link_args() const;
    bool makeRsp();

   private:
    void processDefFile();
    void processInputFiles();
    static StrList processRSPFile(std::string const& rsp_file);
    std::string line_;
    std::string pe_name_;
    std::string implibname_;
    std::string def_file_;
    std::string output_;
    StrList rsp_files_;
    StrList rc_files_;
    StrList command_files_;
    StrList input_files_;
    StrList tokens_;
    bool is_exe_;
    std::map<std::string, StrList> piped_args_ = {
        {"export", {}},    {"include", {}}, {"libpath", {}},
        {"ltcg", {}},      {"machine", {}}, {"nodefaultlib", {}},
        {"subsystem", {}}, {"verbose", {}}, {"wx", {}},
    };
};