/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <winnt.h>
#include <fstream>
#include <iosfwd>
#include <iostream>
#include <string>

#include "coff.h"

class CoffReaderWriter {
   private:
    std::fstream pe_stream_;
    std::string file_;

   public:
    explicit CoffReaderWriter(std::string file);
    ~CoffReaderWriter() = default;
    bool Open();
    bool Close();
    bool IsOpen();
    bool IsClosed();
    void ReadHeader(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in);
    void ReadMember(PIMAGE_ARCHIVE_MEMBER_HEADER head, coff_member* coff_in);
    bool ReadSig(coff& coff_in);
    void write(char* in, int size);
    void read(char* out, int size);
    void seek(int bytes = -1, std::ios_base::seekdir way = std::ios_base::beg);
    int peek();
    void clear();
    void flush();
    std::string get_file();
    std::streampos tell();
    bool end();
};