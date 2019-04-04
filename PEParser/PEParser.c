// PEParser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "printdata.h"
#include "utility.h"

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf_s("error: A path to a PE file is required\n");
        return -1;
    }

    HANDLE fileHandle = NULL, mappingHandle = NULL;
    BYTE* buffer;

    if (MapPEFile(argv[1], &fileHandle, &mappingHandle, &buffer))
        return -1;


    const IMAGE_DOS_HEADER* imageDOSHeader = (const IMAGE_DOS_HEADER*)buffer;
    if (imageDOSHeader->e_magic != 0x5A4D)
    {
        printf_s("error: The file is not a valid PE 32bit file\n");
        UnmapPEFile(fileHandle, mappingHandle);
        return -1;
    }

    const IMAGE_NT_HEADERS32* imageNTHeader = (const IMAGE_NT_HEADERS32*)(buffer + imageDOSHeader->e_lfanew);
    if (imageNTHeader->Signature != 0x00004550)
    {
        printf_s("error: The file is not a valid PE 32bit file\n");
        UnmapPEFile(fileHandle, mappingHandle);
        return -1;
    }

    const IMAGE_FILE_HEADER* imageFileHeader = &imageNTHeader->FileHeader;
    const IMAGE_OPTIONAL_HEADER32* imageOptionalHeader = &imageNTHeader->OptionalHeader;
    if (imageOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && imageOptionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        printf_s("error: The file is not a valid PE 32bit file\n");
        UnmapPEFile(fileHandle, mappingHandle);
        return -1;
    }

    const IMAGE_DATA_DIRECTORY* imageDataDirectories = imageOptionalHeader->DataDirectory;
    const IMAGE_SECTION_HEADER* imageSectionHeaders = (const IMAGE_SECTION_HEADER*)((BYTE*)imageDataDirectories
        + imageOptionalHeader->NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY));

    PrintFileHeader(imageFileHeader);
    PrintOptionalHeader(imageOptionalHeader, imageSectionHeaders, imageFileHeader->NumberOfSections);
    PrintSections(imageSectionHeaders, imageFileHeader->NumberOfSections);
    PrintExports(
        imageSectionHeaders,
        imageFileHeader->NumberOfSections,
        buffer,
        imageDataDirectories[0].VirtualAddress
    );
    PrintImports(
        imageSectionHeaders,
        imageFileHeader->NumberOfSections,
        buffer,
        imageDataDirectories[1].VirtualAddress
    );

    UnmapPEFile(fileHandle, mappingHandle);
    return 0;
}