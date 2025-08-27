/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <windows.h>  // NOLINT
#include <handleapi.h>
#include <winnt.h>
#include <string>
#include "execute.h"

/**
 * @brief Encapsulates a stream for reading and writing to a coff object
 * 
 * Provides abstractions around many common istream stream operations
 * for simple manipulation of the underlying COFF stream by a parser.
 * 
 * Provides additional, coff specific method, to read in specific types of data
 * in a structured format, i.e. ReadHeader reads in exactly enough data to populate
 * a coff member archive header and the ReadMember method behaves similarly for archive
 * member data. 
 * 
 * This class is designed for use by a CoffParser class, which should use this class to navigate
 * around and read in the relevant COFF data into memory and then parse it as it sees fit.
 * 
 * This class also provides a writer interface for said parser to write data to the COFF file.
 * This is not structured and expects to recives a series of bytes to write into the COFF binary.
 */

class LibRename {
   public:
    LibRename(std::string p_exe, std::string coff, bool full, bool deploy,
              bool replace);
    LibRename(std::string p_exe, bool full, bool deploy, bool replace);
    bool ExecuteRename();
    bool ExecuteLibRename();
    bool ExecutePERename();
    bool ComputeDefFile();
    std::string ComputeRenameLink();
    std::string ComputeDefLine();

   private:
    bool FindDllAndRename(HANDLE& pe_in);
    bool SpackCheckForDll(const std::string& dll_path) const;
    bool RenameDll(char* name_loc, const std::string& dll_path) const;
    ExecuteCommand def_executor;
    ExecuteCommand lib_executor;
    std::string pe;
    std::string coff;
    std::string new_lib;
    std::string def_file;
    std::string tmp_def_file;
    bool full;
    bool deploy;
    bool replace;
    bool is_exe;
};
