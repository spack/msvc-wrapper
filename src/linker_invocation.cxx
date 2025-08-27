/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#include "linker_invocation.h"
#include <string>
#include <utility>
#include "utils.h"

/**
 * Parses the command line of a given linker invocation and stores information
 * about that command line and its associated behavior
 */
LinkerInvocation::LinkerInvocation(std::string linkLine)
    : line_(std::move(linkLine)), is_exe_(true) {
    StrList const tokenized_line = split(this->line_, " ");
    this->tokens_ = tokenized_line;
}

LinkerInvocation::LinkerInvocation(const StrList& linkLine) {
    this->tokens_ = linkLine;
    this->line_ = join(linkLine);
}

/**
 * Parses a linker invocation to extract imformation about the artifacts produced
 * and the obj files used to produce it
 */
void LinkerInvocation::Parse() {
    for (auto token = this->tokens_.begin(); token != this->tokens_.end();
         ++token) {
        std::string normal_token = *token;
        lower(normal_token);
        // implib specifies the eventuall import libraries name_
        // and thus will contain a ".lib" extension, which
        // the next check will process as a library argument
        if (normal_token.find("implib:") != std::string::npos) {
            // If there was nothing after the ":", the
            // previous link command would have failed
            // and : is not a legal character in a name_
            // guarantees this split command produces a vec of
            // len 2
            StrList implib_line = split(*token, ":");
            this->implibname_ = implib_line[1];
        } else if (endswith(normal_token, ".lib")) {
            this->libs_.push_back(*token);
        } else if (normal_token == "/dll" || normal_token == "-dll") {
            this->is_exe_ = false;
        } else if (startswith(normal_token, "-out") ||
                   startswith(normal_token, "/out")) {
            this->output_ = split(*token, ":")[1];
        } else if (endswith(normal_token, ".obj")) {
            this->objs_.push_back(*token);
        } else if (normal_token.find("def:") != std::string::npos) {
            StrList def_line = split(*token, ":");
            this->def_file_ = def_line[1];
        } else if (startswith(normal_token, "@") &&
                   endswith(normal_token, ".rsp")) {
            // RSP files are used to describe object files, libraries, other CLI
            // Switches relevant to the tool the rsp file is being passed to
            // Primarily utilized by CMake and MSBuild projects to bypass
            // Command line length limits
            this->rsp_file_ = *token;
        }
    }
    std::string const ext = this->is_exe_ ? ".exe" : ".dll";
    if (this->output_.empty()) {
        this->output_ = strip(this->objs_.front(), ".obj") + ext;
    }
    this->name_ = strip(this->output_, ext);
    if (this->implibname_.empty()) {
        this->implibname_ = this->name_ + ".lib";
    }
}

std::string LinkerInvocation::get_name() {
    return this->name_;
}

std::string LinkerInvocation::get_implib_name() {
    return this->implibname_;
}

std::string LinkerInvocation::get_def_file() {
    return this->def_file_;
}

std::string LinkerInvocation::get_rsp_file() {
    return this->rsp_file_;
}

std::string LinkerInvocation::get_out() {
    return this->output_;
}

std::string LinkerInvocation::get_mangled_out() {
    return mangle_name(this->output_);
}

bool LinkerInvocation::IsExeLink() {
    return this->is_exe_ || endswith(this->output_, ".exe");
}
