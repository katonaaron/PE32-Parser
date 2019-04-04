// PEParser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"

#include "error.h"
#include "data.h"

int MapPEFile(const char* FilePath, HANDLE* FileHandle, HANDLE* MappingHandle, BYTE** Buffer)
{
    if (NULL == FilePath || NULL == FileHandle || NULL == MappingHandle || NULL == Buffer)
    {
        PrintError(PE_INVALID_PARAMETER, "MapPEFile");
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
        PrintError(GetLastError(), "CreateFile");
        retVal = -1;
        goto cleanup;
    }
    rollback = 1;

    if (!GetFileSizeEx(fileHandle, &fileSize))
    {
        PrintError(GetLastError(), "GetFileSizeEx");
        retVal = -1;
        goto cleanup;
    }

    if (fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER))
    {
        PrintError(PE_INVALID_FILE);
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
        PrintError(GetLastError(), "CreateFileMapping");
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
        PrintError(GetLastError(), "MapViewOfFile");
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

    for (int i = 0; i < NumberOfSections; i++)
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

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        PrintError(PE_NO_INPUT_FILE);
        return -1;
    }

    HANDLE fileHandle = NULL, mappingHandle = NULL;
    BYTE* buffer;



    if (MapPEFile(argv[1], &fileHandle, &mappingHandle, &buffer))
        return -1;


    const IMAGE_DOS_HEADER* imageDOSHeader = (const IMAGE_DOS_HEADER*)buffer;
    if (imageDOSHeader->e_magic != 0x5A4D)
    {
        PrintError(PE_INVALID_FILE);
        UnmapPEFile(fileHandle, mappingHandle);
        return -1;
    }

    const IMAGE_NT_HEADERS32* imageNTHeader = (const IMAGE_NT_HEADERS32*)(buffer + imageDOSHeader->e_lfanew);
    if (imageNTHeader->Signature != 0x00004550)
    {
        PrintError(PE_INVALID_FILE);
        UnmapPEFile(fileHandle, mappingHandle);
        return -1;
    }

    const IMAGE_FILE_HEADER* imageFileHeader = &imageNTHeader->FileHeader;
    const IMAGE_OPTIONAL_HEADER32* imageOptionalHeader = &imageNTHeader->OptionalHeader;
    if (imageOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && imageOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PrintError(PE_INVALID_FILE);
        UnmapPEFile(fileHandle, mappingHandle);
        return -1;
    }

    const IMAGE_DATA_DIRECTORY* imageDataDirectories = imageOptionalHeader->DataDirectory;
    const IMAGE_SECTION_HEADER* imageSectionHeaders = (const IMAGE_SECTION_HEADER*)((BYTE*)imageDataDirectories
        + imageOptionalHeader->NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY));

    const IMAGE_IMPORT_DESCRIPTOR* importTable = NULL;

    PE_DATA data = {
        imageFileHeader->Machine,
        imageFileHeader->NumberOfSections,
        imageFileHeader->Characteristics,
        0,
        imageOptionalHeader->ImageBase,
        imageOptionalHeader->SectionAlignment,
        imageOptionalHeader->FileAlignment,
        imageOptionalHeader->Subsystem,
        imageOptionalHeader->NumberOfRvaAndSizes,
        NULL
    };

    data.Sections = (PE_SECTIONS*)malloc(sizeof(PE_SECTIONS) * imageFileHeader->NumberOfSections);
    if (NULL == data.Sections)
    {
        PrintError(PE_NO_MEMORY);
        UnmapPEFile(fileHandle, mappingHandle);
        return -1;
    }

    for (int i = 0; i < data.NumberOfSections; i++)
    {
        data.Sections[i].Name = (char*)imageSectionHeaders[i].Name;
        data.Sections[i].FileAddress = imageSectionHeaders[i].PointerToRawData;
        data.Sections[i].Size = imageSectionHeaders[i].SizeOfRawData;

        if (IsInSection(
            imageSectionHeaders[i].VirtualAddress,
            imageSectionHeaders[i].Misc.VirtualSize,
            imageOptionalHeader->AddressOfEntryPoint))
        {
            data.AddressOfEntryPoint = ConvertRVAToFa(
                imageSectionHeaders[i].PointerToRawData,
                imageSectionHeaders[i].VirtualAddress,
                imageOptionalHeader->AddressOfEntryPoint
            );
        }

        if (IsInSection(
            imageSectionHeaders[i].VirtualAddress,
            imageSectionHeaders[i].Misc.VirtualSize,
            imageDataDirectories[1].VirtualAddress))
        {
            importTable = buffer + ConvertRVAToFa(
                imageSectionHeaders[i].PointerToRawData,
                imageSectionHeaders[i].VirtualAddress,
                imageDataDirectories[1].VirtualAddress
            );
        }
    }

    PrintData(&data);

    printf("Imports:\n");

    DWORD address;
    char* DLLName;
    IMAGE_IMPORT_DESCRIPTOR aux = { 0 };

    const IMAGE_IMPORT_BY_NAME* importedFunctions;
    const IMAGE_THUNK_DATA32* imageThunkData;

    int i = 0;
    while (memcmp(importTable + i, &aux, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
    {
        if (!FindPA(imageSectionHeaders, data.NumberOfSections, importTable[i].Name, &address))
        {
            printf("undef\n");
            i++;
            continue;
        }
        DLLName = buffer + address;

        if (!FindPA(imageSectionHeaders, data.NumberOfSections, importTable[i].FirstThunk, &address))
        {
            printf("undef\n");
            i++;
            continue;
        }
        imageThunkData = buffer + address;

        while (imageThunkData->u1.AddressOfData != 0)
        {
            if (IMAGE_ORDINAL_FLAG & imageThunkData->u1.AddressOfData)
            {
                printf("%s,0x%X\n", DLLName, (WORD)imageThunkData->u1.Ordinal);
            }
            else
            {
                if (!FindPA(imageSectionHeaders, data.NumberOfSections, imageThunkData->u1.AddressOfData, &address))
                {
                    printf("undef\n");
                    continue;
                }
                importedFunctions = buffer + address;
                printf("%s,%s\n", DLLName, importedFunctions->Name);
            }
            
            imageThunkData++;
        }
        i++;
    }


    free(data.Sections);
    UnmapPEFile(fileHandle, mappingHandle);
    return 0;
}