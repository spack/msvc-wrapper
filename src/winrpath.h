#pragma once

#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <winnt.h>
#include <strsafe.h>

#include "utils.h"
#include "execute.h"

#pragma pack(push, r1, 1)
typedef struct coff_member {
    char data[];
} coff_member;

typedef struct coff_header {
    char file_name[16];
	char modification_timestamp[12];
	char owner_id[6];
	char group_id[6];
	char file_mode[8];
	char file_size[10];
	wchar_t end_marker;
} coff_header;
#pragma pack(pop, r1)

typedef struct coff_entry {
    std::streampos offset;
    coff_header header;
    coff_member member;
} coff_entry;

typedef struct coff {
    char signature[IMAGE_ARCHIVE_START_SIZE];
    std::vector<coff_entry> members;
} coff;

/**
 * @brief Encapsulates a stream reading a COFF file object
 */
class CoffReader {
private:
    std::fstream pe_stream;
    std::string _file;
public:
    CoffReader(std::string file);
    ~CoffReader() = default;
    bool Open();
    bool Close();
    bool isOpen();
    bool isClosed();
    void read_header(coff_header * coff_in);
    void read_member(coff_header head, coff_member * coff_in);
    void read_sig(char * sig);
    void write_name(char * name, int size);
    void seek(int bytes=-1);
    std::streampos tell();
    bool end();

};

class CoffParser {
private:
    CoffReader* coffStream;
    coff coff_;
    std::vector<std::string> names;
    void parse_names();
public:
    CoffParser(CoffReader * cr);
    ~CoffParser() = default;
    bool parse();
    bool is_imp_lib();
    bool normalize_name();
};

class LinkerInvocation {
public:
    LinkerInvocation(const std::string &linkLine);
    LinkerInvocation(const StrList &linkline);
    ~LinkerInvocation() = default;
    void parse();
    bool is_exe_link();
    std::string get_name();
private:
    std::string line;
    std::vector<std::string> tokens;
    std::string name;
    std::string output;
    std::vector<std::string> libs;
    bool is_exe;
};


class LibRename {
public:
    LibRename(std::string lib, std::string name, bool replace);
    void executeLibRename();
    void computeDefFile();
    std::string compute_rename_line();
    std::string compute_def_line();

private:
    ExecuteCommand def_executor;
    ExecuteCommand lib_executor;
    std::string lib;
    std::string name;
    std::string new_lib;
    std::string def_file;
    bool replace;
};


class WinRPathRenameException : public std::exception {
public:
    WinRPathRenameException(std::string msg) : message(msg) {}
    char const * what();
protected:
    std::string message;
};
