/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#include "coff_reader_writer.h"
#include <fileapi.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <cstdio>
#include "coff.h"
#include "coff_parser.h"
#include "coff_pe_reporter.h"
#include "linker_invocation.h"
#include "utils.h"

#include <winnt.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ios>
#include <iosfwd>
#include <iostream>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

CoffReaderWriter::CoffReaderWriter(std::string file)
    : _file(std::move(std::move(file))) {}

bool CoffReaderWriter::Open() {
    this->pe_stream.open(this->_file,
                         std::ios::in | std::ios::out | std::ios::binary);
    return this->pe_stream.is_open();
}

bool CoffReaderWriter::Close() {
    this->pe_stream.close();
    return !this->pe_stream.is_open();
}

void CoffReaderWriter::clear() {
    this->pe_stream.clear();
}

bool CoffReaderWriter::IsOpen() {
    return this->pe_stream.is_open();
}

bool CoffReaderWriter::IsClosed() {
    return !this->pe_stream.is_open();
}

bool CoffReaderWriter::ReadSig(coff& coff_in) {
    this->pe_stream.read(reinterpret_cast<char*>(&coff_in.signature),
                         IMAGE_ARCHIVE_START_SIZE);
    return strcmp(coff_in.signature, IMAGE_ARCHIVE_START) != 0;
}

void CoffReaderWriter::ReadHeader(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in) {
    this->pe_stream.read(reinterpret_cast<char*>(coff_in),
                         sizeof(IMAGE_ARCHIVE_MEMBER_HEADER));
}

void CoffReaderWriter::ReadMember(PIMAGE_ARCHIVE_MEMBER_HEADER head,
                                  coff_member* coff_in) {
    int const member_size = atoi(reinterpret_cast<char*>(head->Size));
    coff_in->data = new char[member_size];
    this->pe_stream.read(coff_in->data, member_size);
    if (member_size % 2 != 0) {
        this->seek(1, std::ios_base::cur);
    }
}

std::string CoffReaderWriter::get_file() {
    return this->_file;
}

std::streampos CoffReaderWriter::tell() {
    return this->pe_stream.tellg();
}

void CoffReaderWriter::seek(int bytes, std::ios_base::seekdir way) {
    this->pe_stream.seekg(bytes, way);
}

int CoffReaderWriter::peek() {
    return this->pe_stream.peek();
}

bool CoffReaderWriter::end() {
    return this->pe_stream.eof();
}

void CoffReaderWriter::read(char* out, int size) {
    this->pe_stream.read(out, size);
}

void CoffReaderWriter::write(char* stream_in, int size) {
    this->pe_stream.write(stream_in, size);
}

/**
 * Flushes the CoffReaderWriter's underlying stream to disk
 * 
 * This is primarily useful in debuging to ensure immediate
 * writes to disk rather than waiting for the buffer to overflow
 * so that operations performed on the coff file can be validated
 * in real time
 */
void CoffReaderWriter::flush() {
    this->pe_stream.flush();
}
