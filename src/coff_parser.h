/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <strsafe.h>
#include <windows.h>  // NOLINT
#include <winnt.h>
#include <string>

#include "coff.h"
#include "coff_reader_writer.h"

class CoffParser {
   private:
    CoffReaderWriter* coffStream_;
    coff coff_;
    bool verified_ = false;
    bool ParseData(PIMAGE_ARCHIVE_MEMBER_HEADER header, coff_member* member);
    static void ParseShortImport(coff_member* member);
    static void ParseFullImport(coff_member* member);
    static void ParseFirstLinkerMember(coff_member* member);
    static void ParseSecondLinkerMember(coff_member* member);
    static void ReportLongImportMember(long_import_member* long_import);
    static void ReportShortImportMember(short_import_member* short_import);
    static void ReportLongName(const char* data);
    void NormalizeLinkerMember(const std::string& name,
                               const size_t& base_offset, const size_t& offset,
                               const char* strings, DWORD symbols);
    void NormalizeSectionNames(const std::string& name, char* section,
                               const DWORD& section_data_start_offset,
                               size_t data_size);
    static bool ValidateLongName(coff_member* member, int size);
    void writeRename(char* name, size_t size, size_t loc);
    static bool matchesName(char* old_name, const std::string& new_name);

   public:
    explicit CoffParser(CoffReaderWriter* coff_reader);
    ~CoffParser() = default;
    bool Parse();
    bool NormalizeName(std::string& name);
    void Report();
    int Verify();
    static int Validate(std::string& coff);
};

bool reportCoff(CoffParser& coff);
