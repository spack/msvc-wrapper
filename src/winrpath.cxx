/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#include <cstdio>
#include <windows.h>  // NOLINT
#include "winrpath.h"
#include <fileapi.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <winnt.h>
#include "coff_parser.h"
#include "coff_reader_writer.h"
#include "execute.h"
#include "regex_utils.h"
#include "utils.h"

#include <fstream>
#include <iosfwd>
#include <iostream>
#include <ostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <regex>

/*
 * Checks a DLL name for path characters
 * 
 *  Path characters are not typically found in DLLs outside of those produced by this compiler wrapper
 *  and as such are an indication this is a Spack produced binary
 * 
 * 
 * \param name The dll name to check for path characters
 * 
*/
bool LibRename::SpackCheckForDll(const std::string& dll_path) {
    return hasPathCharacters(dll_path);
}

/*
 * Actually performs the DLL rename, given the DLL location in mapped memory view
 * determines the required padding for a name, gets the new path to a dll
 * re-pads it, and then writes that into the DLL name location.
 * 
 * \param  name_loc Raw offset to the imported DLL name
 * \param dll_name The dll, in the case we're doing an extraction from the buildcache
 *                  that we'll look for a version of on the current system and rename
 *                  the dll name found at `name_loc` to the absolute path of
 * 
*/
bool LibRename::RenameDll(char* name_loc, const std::string& dll_path) {
    if (SpackInstalledLib(dll_path)) {
        DEBUG_LOG("Spack installed dll reference, no need to relocate");
        return true;
    }
    PathRelocator relocator;
    std::string new_loc = relocator.getRelocation(dll_path);
    if (new_loc.empty()) {
        std::cerr << "Cannot find relocation mapping for library " << dll_path
                  << "\n";
        return false;
    }
    try {
        new_loc =
            EnsureValidLengthPath(CanonicalizePath(MakePathAbsolute(new_loc)));
    } catch (NameTooLongError& e) {
        std::cerr << "Cannot relocate path " << new_loc
                  << "it is too long to be relocated safely.\n";
        return false;
    }

    char* new_lib_pth =
        pad_path(new_loc.c_str(), static_cast<DWORD>(new_loc.size()));
    if (!new_lib_pth) {
        return false;
    }
    replace_special_characters(new_lib_pth, MAX_NAME_LEN);

    // c_str returns a proper (i.e. null terminated) value, so we dont need to worry about
    // size differences w.r.t the path to the new library
    snprintf(name_loc, MAX_NAME_LEN + 1, "%s", new_lib_pth);
    return true;
}

/*
 * Loads DLL into memory the way it would be if loaded by the system
 * This is require behavior as the MSVC structs designed to parse the PE
 * format expect proper page/memory alignment, which is only done if properly
 * mapped into memory.
 * 
 * Decompose the PE file into a series of structs to locate the IMPORT section
 * Parse the IMPORT section for the names of all imported DLLS
 * If a given DLL name is a Spack derived DLL name, identifiable via fact there are 
 * path characters in the DLL name, which is not normally the case without Spack, 
 * depending on the operation, the name is modified.
 * On extraction, we find dll names with path characters and rename (and repad) them with
 * the correct absolute path to the requisite DLL on the new host system.
 * 
 * This approach is heavily based on 
 * https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++#first-dll-name
 * 
 * \param pe_in the PE file for which to perform the imported DLL rename procedure
 * 
 * 
*/
bool LibRename::FindDllAndRename(HANDLE& pe_in) {
    HANDLE h_map_object =
        CreateFileMapping(pe_in, nullptr, PAGE_READWRITE, 0, 0, nullptr);
    if (!h_map_object) {
        std::cerr << "Unable to create mapping object: " << reportLastError()
                  << "\n";
        return false;
    }
    LPVOID basepointer = static_cast<char*>(
        MapViewOfFile(h_map_object, FILE_MAP_WRITE, 0, 0, 0));
    if (!basepointer) {
        std::cerr << "Unable to create file map view\n";
        return false;
    }
    // Establish base PE headers
    auto* dos_header = static_cast<PIMAGE_DOS_HEADER>(basepointer);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Error: Invalid DOS signature (Not an Executable/DLL file).\n";
        return false;
    }
    auto* pe_signature = reinterpret_cast<DWORD*>(
        static_cast<char*>(basepointer) + dos_header->e_lfanew);

    if (*pe_signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Error: Invalid PE signature (Not a Windows PE binary).\n";
        return false;
    }

    auto* coff_header = reinterpret_cast<PIMAGE_FILE_HEADER>(
        static_cast<char*>(basepointer) + dos_header->e_lfanew + sizeof(DWORD));

    auto* raw_optional_ptr = static_cast<char*>(basepointer) + dos_header->e_lfanew +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

    WORD const magic = *reinterpret_cast<WORD*>(raw_optional_ptr);

    DWORD number_of_rva_and_sections = 0;
    DWORD rva_import_directory = 0;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* opt64 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(raw_optional_ptr);
        number_of_rva_and_sections = opt64->NumberOfRvaAndSizes;
        rva_import_directory = opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
        auto* opt32 = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(raw_optional_ptr);
        number_of_rva_and_sections = opt32->NumberOfRvaAndSizes;
        rva_import_directory = opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }

    auto* section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(
        raw_optional_ptr + coff_header->SizeOfOptionalHeader);

    if (number_of_rva_and_sections == 0) {
        std::cerr << "PE file does not import symbols" << "\n";
        return false;
    }
    if (number_of_rva_and_sections < 2) {
        std::cerr << "PE file contains insufficient data directories, likely "
                     "corrupted"
                  << "\n";
        return false;
    }

    if (rva_import_directory == 0) {
        // No import table is valid (e.g. python3.dll which only forwards exports).
        FlushViewOfFile((LPCVOID)basepointer, 0);
        UnmapViewOfFile((LPCVOID)basepointer);
        return SafeHandleCleanup(h_map_object) != 0;
    }

    DWORD const number_of_sections = coff_header->NumberOfSections;
    DWORD const import_section_file_offset = RvaToFileOffset(
        section_header, number_of_sections, rva_import_directory);
    if (import_section_file_offset == 0) {
        std::cerr << "Import table RVA 0x" << std::hex << rva_import_directory
                  << " could not be resolved to a file offset.\n";
        UnmapViewOfFile((LPCVOID)basepointer);
        return false;
    }
    char* import_table_offset =
        static_cast<char*>(basepointer) + import_section_file_offset;
    auto* import_image_descriptor =
        reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(import_table_offset);
    //DLL Imports
    for (; import_image_descriptor->Name != 0; import_image_descriptor++) {
        char* imported_dll =
            import_table_offset +
            (import_image_descriptor->Name - rva_import_directory);
        std::string const str_dll_name = std::string(imported_dll);
        DEBUG_LOG("Considering library: " + str_dll_name + " for relocation");
        if (LibRename::SpackCheckForDll(str_dll_name)) {
            DEBUG_LOG("Spack dll: " + str_dll_name);
            if (!LibRename::RenameDll(imported_dll, str_dll_name)) {
                std::cerr << "Unable to relocate DLL reference: "
                          << str_dll_name << "\n";
                return false;
            }
        }
    }
    FlushViewOfFile((LPCVOID)basepointer, 0);
    UnmapViewOfFile((LPCVOID)basepointer);

    return SafeHandleCleanup(h_map_object) != 0;
}

/*
 * LibRename is responsible for renaming and relocating DLLs and
 * their corresponding import libraries
 * 
 * Full -   this flag informs the process as to whether we're relocating a DLL or
 *          just its import library. If we're doing a "full" pass, we
 *          produce a new import library with the absolute path to its dll
 *          AND we re-write all external DLL references in the DLL itself. If this
 *          is false and we're not doing a "full" build, we only re-write
 *          the import lib
 * 
 * \param pe the PE file for which to perform the rename of imported (and exported) DLL names
 * \param full a flag indicating whether or not we're renaming a PE file and import lib or just an import lib
 * \param deploy a flag indicating if we're deploying a binary to a Spack build cache or extracting it
 * \param replace a flag indicating if we're replacing the renamed import lib or making a copy with absolute dll names
 * \param report a flag indicating if we should be reporting the contents of the PE/COFF file we're parsing to stdout
*/
LibRename::LibRename(std::string p_exe, bool full, bool replace)
    : replace(replace), full(full), pe(std::move(p_exe)) {
    this->pe = MakePathAbsolute(this->pe);
}

LibRename::LibRename(std::string p_exe, std::string coff, bool full,
                     bool replace)
    : replace(replace),
      full(full),
      pe(std::move(p_exe)),
      coff(std::move(coff)) {
    this->pe = MakePathAbsolute(this->pe);
    std::string const coff_path = stem(this->coff);
    this->tmp_def_file = coff_path + "-tmp.def";
    this->def_file = coff_path + ".def";
    this->def_executor =
        ExecuteCommand("dumpbin.exe", {this->ComputeDefLine()});
    this->lib_executor = ExecuteCommand("lib.exe", {this->ComputeRenameLink()});
}

/**
 * Creates the line to be provided to dumpbin.exe to produce the exports of a given
 * dll in the case where we do not have access to the original link line
 *
 * Produces something like `/EXPORTS <name of coff file>`
 */
std::string LibRename::ComputeDefLine() {
    return "/NOLOGO /EXPORTS \"" + this->coff + "\"";
}

/**
 * Drives the process of running dumpbin.exe on a PE file to determine its exports
 * and produce a `.def` file
 *
 * Returns the return code of the Def file computation operation
 */
bool LibRename::ComputeDefFile() {
    this->def_executor.Execute(this->tmp_def_file);
    DWORD const def_res = this->def_executor.Join();
    // Release the handle used to capture dumpbin's output now, otherwise it
    // stays open (and blocks removal of tmp_def_file below) until def_executor
    // is destroyed.
    this->def_executor.CleanupHandles();
    // tmp_def_file is scratch regardless of outcome; remove it on every
    // exit path, including dumpbin failures that leave partial output
    ScopedFile const tmp_def_cleanup(this->tmp_def_file);
    if (def_res) {
        // dumpbin's stdout and stderr were both captured into tmp_def_file;
        // surface them now, since the file is about to be deleted and this
        // is otherwise the only record of why dumpbin failed
        std::cerr << "dumpbin.exe failed with exit code " << def_res
                  << " while computing exports for " << this->coff << "\n";
        std::ifstream dumpbin_output(this->tmp_def_file);
        if (dumpbin_output.is_open()) {
            std::cerr << dumpbin_output.rdbuf();
        }
        return false;
    }
    std::ifstream input_file(this->tmp_def_file);
    if (!input_file.is_open()) {
        std::cerr << "Error: Could not open input file " << tmp_def_file
                  << '\n';
        return false;
    }
    std::ofstream output_file(this->def_file);
    if (!output_file.is_open()) {
        std::cerr << "Error: Could not open output file " << this->def_file
                  << '\n';
        return false;
    }
    output_file << "EXPORTS\n";
    std::string line;
    while (std::getline(input_file, line)) {
        if (!regexSearch(line, R"(ordinal\s+(?:hint\s+RVA\s+)?name)").empty()) break;
    }
    while (std::getline(input_file, line)) {
        if (line.empty()) {
            continue;
        }
        if (line.find("Summary") != std::string::npos) {
            break;
        }
        output_file << "    "
                    << regexMatch(line, R"(^.*?(\S+)(?:\s+\(.*\))?\s*$)").str(1)
                    << '\n';
    }
    input_file.close();
    output_file.close();
    return true;
}

/**
 * End to end PE + COFF rename process driver
 *  Produces a `.def` file describing the exports of a given PE file
 *  and then generates an import library with absolute paths to the
 *  corresponding dll or generates a dll with absolute paths to its
 *  dependencies depending on the context
 * 
 * Returns 0 on failure, 1 otherwise
 * 
 * On standard deployment, we don't do anything
 * On standard extraction, we want to regenerate the import library
 *  from our import library pointing to the new location of the dll/exe
 *  post buildcache extraction
 *
 * 
 * On a full extraction, in addition to the standard extraction operation
 *  we rename the Dll names that have paths
 *
 */
bool LibRename::ExecuteRename() {
    // If we're not deploying, we're extracting
    // recompute the .def and .lib for dlls and optionally
    // exes
    // We do not bother with defs for things that don't have
    // import libraries
    if (!this->coff.empty()) {
        // Extract DLL
        if (!this->ComputeDefFile()) {
            std::cerr << "Failed to compute def file for " << this->coff
                      << "\n";
            return false;
        }
        if (!this->ExecuteLibRename()) {
            std::cerr << "Failed to create and rename import lib for "
                      << this->coff << "\n";
            return false;
        }
    }
    if (this->full) {
        if (!this->ExecutePERename()) {
            std::cerr << "Unable to execute rename of "
                         "referenced components in PE file: "
                      << this->pe << "\n";
            return false;
        }
    }
    return true;
}

/**
 * Drives the rename procedure for an import library
 *   Creates a new import library from a def file with
 *   a mangled variation of the absolute path to the dll
 *   as its dll name, and then modifies that binary to correct
 *   and unmangle the mangled dll name
 * 
 */
bool LibRename::ExecuteLibRename() {
    this->lib_executor.Execute();
    DWORD const ret_code = this->lib_executor.Join();
    // lib.exe has consumed the def file at this point; it and lib.exe's
    // outputs (the temporary import lib, which the rename below consumes
    // on success, and a .exp byproduct) are scratch — make sure none of
    // them survive this function, whichever path exits it
    ScopedFile const def_cleanup(this->def_file);
    ScopedFile const new_lib_cleanup(this->new_lib);
    ScopedFile const exp_cleanup(stem(this->new_lib) + ".exp");
    if (ret_code != 0) {
        std::cerr << "Lib Rename failed with exit code: " << ret_code << "\n";
        return false;
    }
    // replace former .lib with renamed .lib
    if (!ReplaceFileWithRename(this->coff, this->new_lib)) {
        return false;
    }
    // import library has been generated with
    // mangled abs path to dll -
    // unmangle it
    CoffReaderWriter coff_reader(this->coff);
    CoffParser coff_parser(&coff_reader);
    int const coff_parse_valid = coff_parser.Verify();
    if (coff_parse_valid) {
        std::cerr << "Unable to parse generated import library {"
                  << this->new_lib << "}: ";
        std::string const err = coff_parse_valid > 1
                                    ? "Error parsing library\n"
                                    : "Library is static, not import\n";
        std::cerr << err;
        return false;
    }
    try {
        std::string mangled_name = mangle_name(this->pe);
        if (!coff_parser.NormalizeName(mangled_name)) {
            std::cerr << "Unable to normalize name: " << mangled_name << "\n";
            return false;
        }
    } catch (const NameTooLongError& e) {
        std::cerr << "Unable to mangle name, DLL name " << this->pe
                  << " too long\n";
        return false;
    }

    return true;
}

/**
 * Drives the rename process for 
 * 
 */
bool LibRename::ExecutePERename() {
    std::wstring pe_path;
    try {
        pe_path = ConvertASCIIToWide(this->pe);
    } catch (const std::overflow_error& e) {
        std::cerr << e.what() << "\n";
        return false;
    }
    try {
        ScopedFileAccess obtain_write(pe_path, GENERIC_ALL);
        obtain_write.Access();
        HANDLE pe_handle = CreateFileW(
            pe_path.c_str(), (GENERIC_READ | GENERIC_WRITE), FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!pe_handle || pe_handle == INVALID_HANDLE_VALUE) {
            std::cerr << "Unable to acquire file handle to "
                      << ConvertWideToASCII(pe_path) << ": "
                      << reportLastError() << "\n";
            return false;
        }
        return LibRename::FindDllAndRename(pe_handle);
    } catch (const std::system_error& e) {
        std::cerr << "Could not obtain write access: " << e.what()
                  << " (Error Code: " << e.code().value() << ")" << '\n';
        return false;
    }
}

/* Construct the line needed to produce a new import library
 * given a set of symbols exported by a DLL and stored in a module definition (.def) file,
 * the current import lib and a name for said DLL, which in 
 * our case is the mangled DLL absolute path. This creates 
 * an import libray with a mangled absolute path to the DLL 
 * as its DLL name which we then unmangle to produce the "rpath" that
 * will be injected into binaries that link against this.
 * 
 * This method will inject a dll name that is mangled, as in the examples
 * below. A followup step, performed by this wrapper, specifically the CoffParser,
 * is required to actually go into the binary, and un-mangle that name.
 * This is due to constraints placed on the linker and archiver command lines by MS.
 * 
 * A rename line looks something like
 * 
 * -def:foo.def -name:C;|abs|path|to|foo.dll -out:foo.dll-abs.lib foo.lib
 * 
 * If we're replacing the current binary
 * 
 * -def:foo.def -name:C;|abs|path|to|foo.dll -out:foo.lib foo.lib
 * 
*/
std::string LibRename::ComputeRenameLink() {
    std::string line("-def:\"");
    line += this->def_file + "\" ";
    line += "-name:\"";
    line += mangle_name(this->pe) + "\" ";
    std::string const name(stem(this->coff));
    if (!this->replace) {
        this->new_lib = name + ".abs-name.lib";
    } else {
        // Name must be different
        this->new_lib = name + "-tmp.lib";
    }
    line += "-out:\"" + this->new_lib + "\"";
    return line;
}
