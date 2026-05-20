/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include <cstddef>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <numeric>
#include "linker_invocation.h"
#include <errhandlingapi.h>
#include "utils.h"

enum { MaxProcessCommandLength = 32767 };

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
 * Takes a normalized token and determines the appropriate handling 
 * based on the linker command line arguments
 */
void LinkerInvocation::ProcessTokens(const std::string &normal_token, const std::string& token) {
    // implib specifies the eventuall import libraries name_
    // and thus will contain a ".lib" extension, which
    // the next check will process as a library argument
    if (normal_token.find("implib:") != std::string::npos) {
        // If there was nothing after the ":", the
        // previous link command would have failed
        // and : is not a legal character in a name_
        // guarantees this split command produces a vec of
        // len 2
        StrList implib_line = split(token, ":");
        this->implibname_ = implib_line[1];
    } else if (normal_token == "dll") {
        this->is_exe_ = false;
    } else if (startswith(normal_token, "out")) {
        this->output_ = split(token, ":")[1];
    } else if (endswith(normal_token, ".obj") ||
                endswith(normal_token, ".lib") ||
                endswith(normal_token, ".lo")) {
        this->input_files_.push_back(token);
    } else if (startswith(normal_token, "@")) {
        // RSP files are used to describe object files, libraries, other CLI
        // Switches relevant to the tool the rsp file is being passed to
        // Primarily utilized by CMake and MSBuild projects to bypass
        // Command line length limits
        // Since rsp files are essentially expanded in place on the command line
        // i.e objA rspA objC
        // where rspA defines objB the cli would then be
        // objA objB objC
        // so we also need to track them in input_files since the order
        // of their expansion has implications for naming, i.e
        // if rspA was the first input file, the dll/imp name would be objB
        this->processRSPFile(token);
    } else if (endswith(normal_token, ".res")) {
        this->rc_files_.push_back(token);
        this->input_files_.push_back(token);
    } else if (startswith(normal_token, "def")) {
        this->def_file_ = strip(split(token, ":", 1)[1], "\"");
    } else if (this->piped_args_.find(normal_token) !=
                this->piped_args_.end()) {
        this->piped_args_.at(normal_token).emplace_back(token);
    }   
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
        this->ProcessTokens(normal_token, *token);
    }

    // Note for the below: name will never be specified so we only have
    // /out, .def files, and input files
    // To determine internal dll name
    // If a def file was not specified:
    // /name is used
    // if no /name /out is used
    // if no /out or /name use first input file

    // If a def file was specified:
    // LIBRARY
    // otherwise fallback to previous

    // To determine output name
    // /OUT is always overriding
    // If not /OUT and .def file:
    // LIBRARY
    // if no def or no LIBRARY
    // /NAME
    // if no /NAME
    // first input file (post rc expansion)

    this->processDefFile();
    std::string const ext = this->is_exe_ ? ".exe" : ".dll";
    if (this->output_.empty()) {
        // with no "out" argument, the linker
        // will place the file in the CWD
        std::string const name_component = this->input_files_.front();
        std::string const filename = split(name_component, "\\").back();
        this->output_ = join({GetCWD(), stripLastExt(filename)}, "\\") + ext;
    }
    if (this->implibname_.empty()) {
        std::string const name = strip(this->output_, ext);
        this->implibname_ = name + ".lib";
    }
    this->makeRsp();
}


std::string handleQuotedStrings(std::stringstream& ss, std::string &input) {
    std::string token;
    while (ss >> token) {
        input += " " + token;
        if (token.back() == '"') {
            break;
        }
    }
    input = stripquotes(input);
    return input;
}


void LinkerInvocation::processRSPFile(std::string const& rsp_file) {
    std::string const rsp_file_in = lstrip(rsp_file, "@");
    std::ifstream rsp_stream(rsp_file_in);
    if (!rsp_stream) {
        std::cerr << "Error: Could not open input rsp file: " << rsp_file_in
                  << "\n";
        throw FileIOError("Cannot open rsp input file: " + GetLastError());
    }
    std::string line;
    while (std::getline(rsp_stream, line)) {
        std::stringstream rsp_line(line);
        std::string input_token;
        std::string normal_token;
        while(rsp_line >> input_token) {
            normal_token = input_token;
            if (input_token.front() == '"') {
                normal_token = handleQuotedStrings(rsp_line, input_token);
            }
            normalArg(normal_token);
            this->ProcessTokens(normal_token, input_token);
        }
    }
}

/**
 * \brief Ensure command line given to lib.exe is of appropriate length
 * max windows createProcess command line length is 32,767, so if we exceed
 * that, compose all input file args into an rsp.
 * 
 * Writes an rsp file named spack-build.rsp and sets it to be the only 
 * input file for the lib tool
 */
bool LinkerInvocation::makeRsp() {
    int const total_length = std::accumulate(
        this->input_files_.begin(), this->input_files_.end(), 0,
        [](size_t sum, const std::string& s) { return sum + s.size(); });
    if (total_length > MaxProcessCommandLength) {
        std::string const rsp_name = "spack-build.rsp";
        std::ofstream rsp_out(rsp_name);
        if (!rsp_out) {
            std::cerr << "Unable to open rsp out file: spack-build.rsp\n";
            throw FileIOError("Unable to open lib rsp file");
        }
        for (const auto& line : this->input_files_) {
            rsp_out << escape_backslash(line) << "\n";
        }
        rsp_out.close();
        this->input_files_ = {"@" + rsp_name};
        return true;
    }
    return false;
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

    if (this->def_file_.empty()) {
        return;
    }
    // Def from link line
    std::ifstream def_in(this->def_file_);
    if (!def_in) {
        std::cerr << "Error: Could not open input def file: " << this->def_file_
                  << "\n";
        throw FileIOError("Cannot open def input file: " + GetLastError());
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
            this->pe_name_ = stripquotes(this->pe_name_) + ".exe";
            def_file_export_name = true;
        } else if (keyword == "LIBRARY") {
            this->is_exe_ = false;
            def_line >> this->pe_name_;
            this->pe_name_ = stripquotes(this->pe_name_) + ".dll";
            def_file_export_name = true;
        } else {
            exports.push_back(line);
        }
    }
    if (def_file_export_name) {
        // if output is not specified on the command line, this defines the output name
        if (this->output_.empty()) {
            this->output_ = join({GetCWD(), this->pe_name_}, "\\");
        }
        const std::string def_name = stem(this->def_file_);
        const std::string def_path =
            this->def_file_.substr(0, this->def_file_.find(def_name));
        const std::string rename_def = def_path + def_name + "-rename.def";

        std::ofstream def_out(rename_def);
        if (!def_out) {
            std::cerr << "Error: could not open output def file: " << rename_def
                      << "\n";
            throw FileIOError("Cannot open def output file: " + GetLastError());
        }
        for (const auto& line : exports) {
            def_out << line << "\n";
        }
        def_out.close();
        this->def_file_ = rename_def;
    }
    def_in.close();
}

std::string LinkerInvocation::get_implib_name() const {
    return this->implibname_;
}

std::string LinkerInvocation::get_lib_link_args() const {
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

std::string LinkerInvocation::get_def_file() const {
    return this->def_file_;
}

StrList LinkerInvocation::get_rc_files() const {
    return this->rc_files_;
}

StrList LinkerInvocation::get_input_files() const {
    return this->input_files_;
}

std::string LinkerInvocation::get_out() const {
    return this->output_;
}

std::string LinkerInvocation::get_mangled_out() const {
    return mangle_name(this->get_out());
}

bool LinkerInvocation::IsExeLink() const {
    return this->is_exe_ || endswith(this->get_out(), ".exe");
}
