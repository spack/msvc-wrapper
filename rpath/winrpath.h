#pragma once

#include <stdlib.h>
#include <string>
#include <stdio.h>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <winnt.h>
#include <windows.h>
#include <strsafe.h>
#include <filesystem>



#pragma pack(push, r1, 1)
typedef struct coff_member {
    char data[];
};

typedef struct coff_header {
    char file_name[16];
	char modification_timestamp[12];
	char owner_id[6];
	char group_id[6];
	char file_mode[8];
	char file_size[10];
	wchar_t end_marker;
};
#pragma pack(pop, r1)

typedef struct coff_entry {
    std::streampos offset;
    coff_header header;
    coff_member member;
};

typedef struct coff {
    char signature[IMAGE_ARCHIVE_START_SIZE];
    std::vector<coff_entry> members;
};

/**
 * @brief Encapsulates a stream reading a COFF file object
 */
class CoffReader {
private:
    std::fstream pe_stream;
    std::string _file;
public:
    CoffReader(std::string file);
    ~CoffReader();
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
    ~CoffParser();
    bool parse();
    bool is_imp_lib();
    bool normalize_name();
    bool add_placeholder();
    bool relocate();
};

class LinkerInvocation {
private:
    std::string line;
    std::vector<std::string> tokens;
    std::string name;
    std::string output;
    std::vector<std::string> libs;
    bool is_exe;
public:
    LinkerInvocation(std::string linkLine);
    void parse();
    bool is_exe_link();
};


class LibRename {
public:
    LibRename(std::string lib, std::string name, bool replace);
    void setupExecute();
    void executeLibRename();
    void computeDefFile();
    bool pipeChildtoStdOut();
    void createChildPipes();
    std::string pipeChildToString();
    std::string compute_rename_line();
    std::string compute_def_line();
    bool write_def();

private:
    HANDLE ChildStdOut_Rd;
    HANDLE ChildStdOut_Wd;
    PROCESS_INFORMATION procInfo;
    STARTUPINFOW startInfo;
    std::string lib;
    std::string name;
    std::string new_lib;
    std::string def_file;
    bool replace;
};




class LibraryFinder {
private:
    std::map<std::string, std::string> found_libs;
    std::vector<std::string> search_vars;
    std::map<std::string, std::vector<std::string>> evald_search_paths;
    std::filesystem::path finder(std::filesystem::path pth);
    std::filesystem::path finder(std::string pth);
    bool is_system(std::string pth);
public:
    LibraryFinder();
    std::string find_library(std::string lib_name);
    void eval_search_paths();
};

class WinRPathRenameException : public std::exception {
public:
    WinRPathRenameException(std::string msg) : message(msg) {}
    char const * what();
protected:
    std::string message;
};
