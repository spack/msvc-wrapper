/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */

#include "coff_reader_writer.h"
#include "coff.h"

#include <winnt.h>
#include <cstdlib>
#include <cstring>
#include <ios>
#include <iosfwd>
#include <iostream>
#include <string>
#include <utility>

CoffReaderWriter::CoffReaderWriter(std::string const& file)
    : file_(std::move(file)) {}

bool CoffReaderWriter::Open() {
    this->pe_stream_.open(this->file_,
                          std::ios::in | std::ios::out | std::ios::binary);
    return this->pe_stream_.is_open();
}

bool CoffReaderWriter::Close() {
    this->pe_stream_.close();
    return !this->pe_stream_.is_open();
}

void CoffReaderWriter::clear() {
    this->pe_stream_.clear();
}

bool CoffReaderWriter::IsOpen() {
    return this->pe_stream_.is_open();
}

bool CoffReaderWriter::IsClosed() {
    return !this->pe_stream_.is_open();
}

bool CoffReaderWriter::ReadSig(coff& coff_in) {
    this->pe_stream_.read(reinterpret_cast<char*>(&coff_in.signature),
                          IMAGE_ARCHIVE_START_SIZE);
    return strcmp(coff_in.signature, IMAGE_ARCHIVE_START) != 0;
}

void CoffReaderWriter::ReadHeader(PIMAGE_ARCHIVE_MEMBER_HEADER coff_in) {
    this->pe_stream_.read(reinterpret_cast<char*>(coff_in),
                          sizeof(IMAGE_ARCHIVE_MEMBER_HEADER));
}

void CoffReaderWriter::ReadMember(PIMAGE_ARCHIVE_MEMBER_HEADER head,
                                  coff_member* coff_in) {
    int const member_size = atoi(reinterpret_cast<char*>(head->Size));
    coff_in->data = new char[member_size];
    this->pe_stream_.read(coff_in->data, member_size);
    if (member_size % 2 != 0) {
        this->seek(1, std::ios_base::cur);
    }
}

std::string CoffReaderWriter::get_file() {
    return this->file_;
}

std::streampos CoffReaderWriter::tell() {
    return this->pe_stream_.tellg();
}

void CoffReaderWriter::seek(size_t bytes, std::ios_base::seekdir way) {
    this->pe_stream_.seekg(static_cast<long long>(bytes), way);
}

int CoffReaderWriter::peek() {
    return this->pe_stream_.peek();
}

bool CoffReaderWriter::end() {
    return this->pe_stream_.eof();
}

void CoffReaderWriter::read(char* out, int size) {
    this->pe_stream_.read(out, size);
}

void CoffReaderWriter::write(char* stream_in, size_t size) {
    this->pe_stream_.write(stream_in, static_cast<long long>(size));
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
    this->pe_stream_.flush();
}
