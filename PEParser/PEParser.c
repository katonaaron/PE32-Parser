// PEParser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

void PrintError(DWORD Code, char* FunctionName)
{
    if (FunctionName)
        printf("error: %s failed with error code: 0x%x\n", FunctionName, Code);
    else
        printf("error: Invalid parameter for PrintError\n");
}

void PrintErrorMessage(char* Message)
{
    if (Message)
        printf("error: %s\n", Message);
    else
        printf("error: Invalid parameter for PrintErrorMessage\n");
}

int MapPEFile(const char* FilePath, HANDLE* FileHandle, HANDLE* MappingHandle, char** Buffer)
{
    if (NULL == FilePath || NULL == FileHandle || NULL == MappingHandle || NULL == Buffer)
    {
        PrintErrorMessage("Invalid parameter for MapPEFile");
        return -1;
    }

    HANDLE fileHandle = CreateFileA(
        FilePath,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        PrintError(GetLastError(), "CreateFile");
        return -1;
    }

    HANDLE mappingHandle = CreateFileMappingA(
        fileHandle,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );

    if (mappingHandle == INVALID_HANDLE_VALUE)
    {
        CloseHandle(fileHandle);
        PrintError(GetLastError(), "CreateFileMapping");
        return -1;
    }

    void* buffer = MapViewOfFile(
        mappingHandle,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (NULL == buffer)
    {
        CloseHandle(fileHandle);
        CloseHandle(mappingHandle);
        PrintError(GetLastError(), "CreateFileMapping");
        return -1;
    }

    *FileHandle = fileHandle;
    *MappingHandle = mappingHandle;
    *Buffer = (char*)buffer;

    return 0;
}

void UnmapPEFile(HANDLE FileHandle, HANDLE MappingHandle)
{
    CloseHandle(FileHandle);
    CloseHandle(MappingHandle);
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("error: A path to a PE file is required\n");
        return -1;
    }

    HANDLE fileHandle, mappingHandle;
    char* buffer;

    if (MapPEFile(argv[1], &fileHandle, &mappingHandle, &buffer))
        return -1;

    printf("Success");
    UnmapPEFile(fileHandle, mappingHandle);
    return 0;
}