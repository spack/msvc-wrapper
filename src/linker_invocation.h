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
    bool IsExeLink();
    std::string get_name();
    std::string get_out();
    std::string get_mangled_out();
    std::string get_implib_name();
    std::string get_def_file();
    std::string get_rsp_file();
    std::string get_lib_link_args();

   private:
    void processDefFile();
    std::string line_;
    StrList tokens_;
    std::string name_;
    std::string implibname_;
    std::string def_file_;
    std::string rsp_file_;
    std::string output_;
    StrList libs_;
    StrList objs_;
    bool is_exe_;
    std::map<std::string, StrList> piped_args_ = {
        {"export", {}},    {"include", {}}, {"libpath", {}},
        {"ltcg", {}},      {"machine", {}}, {"nodefaultlib", {}},
        {"subsystem", {}}, {"verbose", {}}, {"wx", {}},
    };
};