#pragma once

#include "winrpath.h"

/**
 * Takes a coff header struct and displays it to the terminal
 */
void reportArchiveHeader(const PIMAGE_ARCHIVE_MEMBER_HEADER header)
{
    printf("----------------------------------\n");
    printf("  Name:    %.16s\n", header->Name);
    printf("  Date:    %.16s\n", header->Date);
    printf("  User ID: %.6s\n", header->UserID);
    printf("  Group ID:  %.6s\n", header->GroupID);
    printf("  Mode:     %.6s\n", header->Mode);
    printf("  Size:     %.12s\n", header->Size);
}

