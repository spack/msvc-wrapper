/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>
#include <cctype>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <aclapi.h>
#include <sddl.h>
#include <memory>

#include "version.h"

#define _STRING(m) #m
#define STRING(m) _STRING(m)

/**
 * This MACRO represents an undocumented
 * limit to the potential length of a
 * dll "name" in a COFF/PE file.
 * Names longer than this can cause the 
 * librarian tool (lib.exe) to overwrite
 * sections of the file adjacent to the
 * name.
 * The limit appears to be 143 characters
 * A size of 144 is valid, except in cases
 * where the name in the PE/COFF file must
 * be null terminated, so we use 143
 * to avoid the null terminator causing an
 * overwrite.
 */
#define MAX_NAME_LEN 143

#define MIN_PADDING_THRESHOLD 8

enum ExitConditions {
    SUCCESS = 0,
    CLI_FAILURE,
    REPORT_FAILURE,
    RENAME_FAILURE,
    INVALID_ENVIRONMENT,
    INVALID_TOOLCHAIN,
    TOOLCHAIN_FAILURE,
    LIB_REMOVE_FAILURE,
    NORMALIZE_NAME_FAILURE,
    COFF_PARSE_FAILURE,
    FILE_RENAME_FAILURE,
    CANNOT_OPEN_FILE_FAILURE,
    FILE_IO_FAILURE
};

typedef std::vector<std::string> StrList;

// Environment Helper Methods
std::string GetSpackEnv(const char* env);
std::string GetSpackEnv(const std::string& env);
StrList GetEnvList(const char* envVar, const std::string& delim = ";");
bool ValidateSpackEnv();

// Returns true if command resolves to the running executable, i.e. the
// wrapper has been pointed at itself and would spawn itself forever
bool IsSelf(const std::string& command);

// String helper methods adding cxx20 features to cxx14 //

// Returns true if arg starts with match
bool startswith(const std::string& arg, std::string& match);

// Returns true if arg starts with match
bool startswith(const std::string& arg, const char* match);

// Returns true of arg ends with match
bool endswith(const std::string& arg, std::string& match);

// Returns true of arg ends with match
bool endswith(const std::string& arg, char const* match);

// Converts W-char (std::wstring) string to ASCII (std::string) string
std::string ConvertWideToASCII(const std::wstring& wstr);

// Converts ASCII (std::string) to wide string (std::wstring)
std::wstring ConvertASCIIToWide(const std::string& str);

// Splits argument "s" by delineator delim
// Returns vector of strings, if delim is present
// Returns a single item list
StrList split(const std::string& s, const std::string& delim,
              const u_int count = 0);

//Strips substr off the RHS of the larger string
std::string strip(const std::string& s, const std::string& substr);

//Strips substr of LHS of the larger string
std::string lstrip(const std::string& s, const std::string& substr);

//Strips off leading and trailing quotes
std::string stripquotes(const std::string& str);

// Joins vector of strings by join character
std::string join(const StrList& args, const std::string& join_char = " ");

// Returns filename stem
std::string stem(const std::string& file);

// Returns file basename
std::string basename(const std::string& file);

// Strips parent paths from path
void StripPath(std::string& command);

// Strips .exe extension from path
void StripExe(std::string& command);

std::string stripLastExt(const std::string& path);

// Drives both StripPath and StripExe on the same path
// resulting in a parentless, non exe extensioned path
void StripPathAndExe(std::string& command);

// Make str lowercase
void lower(std::string& str);

// Given a string containing something terminated by a
// forward slash, get the length of the substr terminated
// by /
int get_slash_name_length(const char* slash_name);

// Implementation of strstr but serch is bounded at size and
// does not terminate on the first read nullptr
char* findstr(char* search_str, const char* substr, size_t size);

// Adds quote to relevent strings in a list of strings
// Strings to be quoted contain: spaces, or any of &<>|()
// These are all legal path characters than have additional
// side effects on Windows
void quoteList(StrList& args);

void quoteAsNeeded(std::string& str);

// FS/Path helpers //

// Returns current working directory
std::string GetCWD();

// Returns boolean indication whether pth is absolute
bool IsPathAbsolute(const std::string& pth);

bool hasPathCharacters(const std::string& name);

std::string short_name(const std::string& path);

std::string mangle_name(const std::string& name);

std::string CanonicalizePath(const std::string& path);

int get_padding_length(const std::string& name);

char* pad_path(const char* pth, DWORD str_size, char padding_char = '|',
               DWORD bsize = MAX_NAME_LEN);

std::string escape_backslash(const std::string& path);

void replace_path_characters(char* path, size_t len);

void replace_special_characters(char* mangled, size_t len);

bool SpackInstalledLib(const std::string& lib);

std::string MakePathAbsolute(const std::string& path);

std::string EnsureValidLengthPath(const std::string& path);

// File and File handle helpers //
/**
 * @brief Returns boolean indicating whether
 * the given file exists
 * 
 * @param fname file to check for existence
 * 
 * @return true if fname exists, false otherwise
 */
bool fileExists(const std::string& fname);

/**
 * @brief Swaps `replacement` in for `original` on disk (used to promote a
 * freshly regenerated import library over the one it replaces).
 *
 * The original file may have been extracted from a buildcache with the
 * Read-Only attribute set (and may lack an ACL entry granting us write
 * access), which would cause the remove to fail. If that happens, a
 * subsequent rename would silently no-op (the destination still exists),
 * leaving `replacement` orphaned on disk and `original` untouched. Write
 * access is obtained first so failures here are real failures.
 *
 * @param original path to the file being replaced
 * @param replacement path to the file to rename over `original`
 *
 * @return true on success, false (with a diagnostic on stderr) otherwise
 */
bool ReplaceFileWithRename(const std::string& original,
                           const std::string& replacement);

// Returns File offset given RVA
DWORD RvaToFileOffset(PIMAGE_SECTION_HEADER& section_header,
                      DWORD number_of_sections, DWORD rva);

// Error checked handle cleanup to ensure all file handles are appropriately closed
// while avoiding closing an already closed or in use handle
int SafeHandleCleanup(HANDLE& handle);

// System Helpers //
std::string reportLastError();

struct LocalFreeDeleter {
    void operator()(void* p) const {
        if (p)
            ::LocalFree(p);
    }
};

// Custom deleter for Standard C pointers.
struct FreeDeleter {
    void operator()(void* p) const {
        if (p)
            std::free(p);
    }
};

// Data helpers //

// Converts big endian data to little endian form
// Windows is little endian, but stores some values in PE
// files in big endian format
DWORD ToLittleEndian(DWORD val);

// Operating Utils //

/**
 * Returns true if debug reporting is on, either because the wrapper was
 * invoked with --debug/-d or because SPACK_DEBUG_WRAPPER is set. The
 * environment is consulted once per process, not once per message.
 */
bool DebugEnabled();

// Forces debug reporting on regardless of the environment
void SetDebug(bool enabled);

void debug(const std::string& dbgStmt);

void debug(char* dbgStmt, int len);

/**
 * Emits a debug message.
 *
 * Always prefer this over calling debug() directly: the wrapper runs once per
 * compiled source file, and a bare debug() call still pays for building its
 * message (string concatenation, typeid, whole command lines) even when
 * reporting is off. This checks first and builds second.
 */
#define DEBUG_LOG(dbgStmt)          \
    do {                            \
        if (DebugEnabled()) {       \
            debug(dbgStmt);         \
        }                           \
    } while (0)

bool isCommandArg(const std::string& arg, const std::string& command);

void normalArg(std::string& arg);

class PathRelocator {
   private:
    bool bc_ = true;
    std::map<std::string, std::string> old_new_map;
    std::string relocateBC(std::string const& pe);
    std::string relocateStage(std::string const& pe);
    void parseRelocate();

   public:
    PathRelocator();
    std::string getRelocation(std::string const& pe);
};

using ScopedLocalInfo = std::unique_ptr<void, LocalFreeDeleter>;

using ScopedSid = std::unique_ptr<void, FreeDeleter>;

class FileSecurity {
   public:
    FileSecurity() = delete;

    static ScopedSid GetCurrentUserSid();

    static bool AclHasAccess(const std::wstring& file_path, DWORD access_mask,
                              PSID sid);

    static bool AddAccessControlEntry(const std::wstring& file_path,
                                DWORD access_mask, PSID sid,
                                PSECURITY_DESCRIPTOR* out_old_sd);

    static bool SetAclFromDescriptor(const std::wstring& file_path,
                                PSECURITY_DESCRIPTOR sd);

    // Retrieves file attributes (e.g., ReadOnly, Hidden).
    // Returns false if the file cannot be accessed.
    static bool GetAttributes(const std::wstring& file_path, DWORD* out_attr);

    // Sets file attributes.
    // Returns false if the operation fails.
    static bool SetAttributes(const std::wstring& file_path, DWORD attr);
};

class ScopedFileAccess {
   public:
    explicit ScopedFileAccess(std::wstring file_path,
                              DWORD desired_access = GENERIC_WRITE);
    ~ScopedFileAccess();
    void Access();

    bool IsAccessGranted() const;

   private:
    std::wstring file_path_;
    DWORD desired_access_;

    // ACL State
    PSECURITY_DESCRIPTOR original_sd_;
    ScopedSid current_user_sid_;
    bool acl_needs_revert_;

    // Attribute State
    DWORD original_attributes_;
    bool attributes_changed_;
};

/**
 * Removes a temporary file when the enclosing scope exits
 *
 * A missing file at destruction time is not an error; it simply means the
 * file was consumed by an intermediate step (or never produced).
 */
class ScopedFile {
   public:
    explicit ScopedFile(std::string file_path);
    ScopedFile(std::string file_path, bool keep);
    ~ScopedFile();
    ScopedFile(const ScopedFile&) = delete;
    ScopedFile& operator=(const ScopedFile&) = delete;
    ScopedFile(ScopedFile&&) noexcept;
    ScopedFile& operator=(ScopedFile&&) noexcept;
    std::string file() const;

   private:
    std::string file_path_;
    bool keep_;
};

const std::map<char, char> special_character_to_path{{'|', '\\'}, {';', ':'}};

const std::map<char, char> path_to_special_characters{{'\\', '|'},
                                                      {'/', '|'},
                                                      {':', ';'}};

class NameTooLongError : public std::runtime_error {
   public:
    explicit NameTooLongError(char const* const message);
    virtual char const* what() const;
};

class FileNotExist : public std::runtime_error {
    public:
     explicit FileNotExist(char const* const message);
     virtual char const * what() const;
};

class SFNProcessingError : public std::runtime_error {
    public:
      explicit SFNProcessingError(char const * const message);
      virtual char  const* what() const;
};

class RCCompilerFailure : public std::runtime_error {
   public:
    RCCompilerFailure(char const* const message);
    virtual char const* what() const;
};

class FileIOError : public std::runtime_error {
   public:
    FileIOError(char const* const message);
    virtual char const* what() const;
};
