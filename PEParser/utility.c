#include "pch.h"
#include "utility.h"

DWORD ConvertRVAToFa(DWORD SectionPA, DWORD SectionVA, DWORD VA)
{
    return SectionPA + VA - SectionVA;
}

BOOL IsInSection(DWORD SectionVA, DWORD SectionSize, DWORD VA)
{
    return SectionVA <= VA && SectionVA + SectionSize > VA;
}

BOOL FindPA(const IMAGE_SECTION_HEADER* imageSectionHeaders, DWORD NumberOfSections, DWORD VA, DWORD* PA)
{
    if (NULL == imageSectionHeaders || NULL == PA)
        return FALSE;

    for (unsigned i = 0; i < NumberOfSections; i++)
    {

        if (IsInSection(
            imageSectionHeaders[i].VirtualAddress,
            imageSectionHeaders[i].Misc.VirtualSize,
            VA))
        {
            *PA = ConvertRVAToFa(
                imageSectionHeaders[i].PointerToRawData,
                imageSectionHeaders[i].VirtualAddress,
                VA
            );
            return TRUE;
        }
    }

    return FALSE;
}

DWORD FindInArray(const WORD* Array, DWORD Size, DWORD Value)
{
    if (NULL == Array || 0 == Size)
        return -1;

    for (DWORD i = 0; i < Size; i++)
    {
        if (Array[i] == Value)
            return i;
    }
    return -1;
}

int MapPEFile(const char* FilePath, HANDLE* FileHandle, HANDLE* MappingHandle, BYTE** Buffer)
{
    if (NULL == FilePath || NULL == FileHandle || NULL == MappingHandle || NULL == Buffer)
    {
        printf_s("error: Invalid parameter was given to \"MapPEFile\"\n");
        return -1;
    }

    int rollback = 0, retVal = 0;
    HANDLE fileHandle = NULL, mappingHandle = NULL;
    LARGE_INTEGER fileSize;
    void* buffer;

    fileHandle = CreateFileA(
        FilePath,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        printf_s("error: \"CreateFile\" failed with error code: 0x%x\n", GetLastError());
        retVal = -1;
        goto cleanup;
    }
    rollback = 1;

    if (!GetFileSizeEx(fileHandle, &fileSize))
    {
        printf_s("error: \"GetFileSizeEx\" failed with error code: 0x%x\n", GetLastError());
        retVal = -1;
        goto cleanup;
    }

    if (fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))//TODO: change size
    {
        printf_s("error: The file is not a valid PE 32bit file\n");
        retVal = -1;
        goto cleanup;
    }

    mappingHandle = CreateFileMappingA(
        fileHandle,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );
    if (mappingHandle == INVALID_HANDLE_VALUE)
    {
        printf_s("error: \"CreateFileMapping\" failed with error code: 0x%x\n", GetLastError());
        retVal = -1;
        goto cleanup;
    }
    rollback = 2;

    buffer = MapViewOfFile(
        mappingHandle,
        FILE_MAP_READ,
        0,
        0,
        0
    );
    if (NULL == buffer)
    {
        printf_s("error: \"MapViewOfFile\" failed with error code: 0x%x\n", GetLastError());
        retVal = -1;
        goto cleanup;
    }

    *FileHandle = fileHandle;
    *MappingHandle = mappingHandle;
    *Buffer = (char*)buffer;

cleanup:
    switch (rollback)
    {
    case 2:
        CloseHandle(mappingHandle);
    case 1:
        CloseHandle(fileHandle);
    default:
        break;
    }
    return retVal;
}

void UnmapPEFile(HANDLE FileHandle, HANDLE MappingHandle)
{
    CloseHandle(FileHandle);
    CloseHandle(MappingHandle);
}