/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include "linker_invocation.h"
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
        normalArg(normal_token);
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
        } else if (normal_token == "dll") {
            this->is_exe_ = false;
        } else if (startswith(normal_token, "out")) {
            this->output_ = split(*token, ":")[1];
        } else if (endswith(normal_token, ".obj")) {
            this->objs_.push_back(*token);
        } else if (startswith(normal_token, "@") &&
                   endswith(normal_token, ".rsp")) {
            // RSP files are used to describe object files, libraries, other CLI
            // Switches relevant to the tool the rsp file is being passed to
            // Primarily utilized by CMake and MSBuild projects to bypass
            // Command line length limits
            this->rsp_file_ = *token;
        } else if (startswith(normal_token, "def")) {
            this->def_file_ = strip(split(*token, ":", 1)[1], "\"");
        } else if (this->piped_args_.find(normal_token) !=
                   this->piped_args_.end()) {
            this->piped_args_.at(normal_token).emplace_back(*token);
        }
    }
    // If we have a def file and no name, attempt to
    // scrape the def file for a name to be sure
    // we respect the intended project name
    // vs overriding via the CLI
    if (!this->def_file_.empty() && this->output_.empty()) {
        this->processDefFile();
    }
    std::string const ext = this->is_exe_ ? ".exe" : ".dll";
    // If output wasn't defined on the command line
    // or the def file
    // compute it based on the same logic as the linker
    // i.e. first obj file name
    if (this->output_.empty()) {
        // with no "out" argument, the linker
        // will place the file in the CWD
        std::string const name_obj = this->objs_.front();
        std::string const filename = split(name_obj, "\\").back();
        this->output_ = join({GetCWD(), strip(filename, ".obj")}, "\\") + ext;
    }
    if (this->implibname_.empty()) {
        std::string const name = strip(this->output_, ext);
        this->implibname_ = name + ".lib";
    }
}

/**
 * processDefFile reads a def file passed to the linker
 *  looking for either LIBRARY or NAME keywords
 *  If found the LinkerInvocation name_ attribute is assigned
 *  to the def file defined library name
 *  and the def file is re-written without that name for use
 *  if our lib pass so we can easily compose an absolute path'd
 *  version of that name
 */
void LinkerInvocation::processDefFile() {

    // Def from link line
    std::ifstream def_in(this->def_file_);
    if (!def_in) {
        std::cerr << "Error: Could not open input def file: " << this->def_file_
                  << "\n";
    }

    std::string line;
    bool def_file_export_name = false;
    StrList exports;

    while (std::getline(def_in, line)) {
        std::stringstream def_line(line);
        std::string keyword;
        def_line >> keyword;

        // extract the intended output library name, overwrite
        // default name derived from first obj file
        // We can leave this def file is as we override on the
        // CLI
        // Name renames exes
        // Library renames DLLs
        // These def keywords override the command line use
        // of /DLL
        if (keyword == "NAME") {
            this->is_exe_ = true;
            def_line >> this->pe_name_;
            this->pe_name_ = this->pe_name_ + ".exe";
            def_file_export_name = true;
        } else if (keyword == "LIBRARY") {
            this->is_exe_ = false;
            def_line >> this->pe_name_;
            this->pe_name_ = this->pe_name_ + ".dll";
            def_file_export_name = true;
        } else {
            exports.push_back(line);
        }
    }
    if (def_file_export_name) {
        const std::string def_name = stem(this->def_file_);
        const std::string def_path =
            this->def_file_.substr(0, this->def_file_.find(def_name));
        const std::string rename_def = def_path + def_name + "-rename.def";

        std::ofstream def_out(rename_def);
        if (!def_out) {
            std::cerr << "Error: could not open output def file: " << rename_def
                      << "\n";
        }
        for (const auto& line : exports) {
            def_out << line << "\n";
        }
        def_out.close();
        this->def_file_ = rename_def;
    }
    def_in.close();
}

std::string LinkerInvocation::get_implib_name() {
    return this->implibname_;
}

std::string LinkerInvocation::get_lib_link_args() {
    std::string lib_link_line;
    for (const auto& var_args : this->piped_args_) {
        // Most of these should be single arguments
        // however some can be defined multiple times
        // namely libpath and include
        // this allows for all arguments to be processed
        // correctly
        auto vars = var_args.second;
        if (!vars.empty()) {
            lib_link_line += join(var_args.second);
        }
    }
    return lib_link_line;
}

std::string LinkerInvocation::get_def_file() {
    return this->def_file_;
}

std::string LinkerInvocation::get_rsp_file() {
    return this->rsp_file_;
}

std::string LinkerInvocation::get_out() {
    return this->output_.empty() ? this->pe_name_ : this->output_;
}

std::string LinkerInvocation::get_mangled_out() {
    return mangle_name(this->get_out());
}

bool LinkerInvocation::IsExeLink() {
    return this->is_exe_ || endswith(this->get_out(), ".exe");
}
