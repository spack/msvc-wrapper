#include <iostream>
#include <string>
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <strsafe.h>

#define BUFSIZE 100

int main(int argc, char ** argv) {
    HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    char buff[BUFSIZE];
    WriteFile(stdOut, buff, 0, NULL, NULL);
}