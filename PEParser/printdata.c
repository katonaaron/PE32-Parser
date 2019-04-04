#include "pch.h"
#include "printdata.h"

void PrintFileHeader(const IMAGE_FILE_HEADER* ImageFileHeader)
{
    printf("File Header:\n");
    printf("-Machine:0x%X\n", ImageFileHeader->Machine);
    printf("-NumberOfSections:0x%X\n", ImageFileHeader->NumberOfSections);
    printf("-Characteristics:0x%X\n", ImageFileHeader->Characteristics);
}

void PrintOptionalHeader(
    const IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader, 
    const IMAGE_SECTION_HEADER* ImageSectionHeaders, 
    WORD NumberOfSections
)
{
    printf("Optional Header:\n");

    DWORD address;
    if (!FindPA(ImageSectionHeaders, NumberOfSections, ImageOptionalHeader->AddressOfEntryPoint, &address))
        printf("-AddressOfEntryPoint:undef\n");
    else
        printf("-AddressOfEntryPoint:0x%X\n", address);

    printf("-ImageBase:0x%X\n", ImageOptionalHeader->ImageBase);
    printf("-SectionAlignment:0x%X\n", ImageOptionalHeader->SectionAlignment);
    printf("-FileAlignment:0x%X\n", ImageOptionalHeader->FileAlignment);
    printf("-Subsystem:0x%X\n", ImageOptionalHeader->Subsystem);
    printf("-NumberOfRvaAndSizes:0x%X\n", ImageOptionalHeader->NumberOfRvaAndSizes);
}

void PrintSections(const IMAGE_SECTION_HEADER* ImageSectionHeaders, WORD NumberOfSections)
{
    printf("Sections:\n");
    for (int i = 0; i < NumberOfSections; i++)
    {
        printf("%.8s,0x%X,0x%X\n", (char*)ImageSectionHeaders[i].Name, ImageSectionHeaders[i].PointerToRawData, ImageSectionHeaders[i].SizeOfRawData);
    }
}

void PrintImports(const IMAGE_SECTION_HEADER* imageSectionHeaders, DWORD NumberOfSections, const BYTE* Buffer, DWORD ImportTableVA)
{
    printf("Imports:\n");

    DWORD address;
    const char* DLLName;
    const IMAGE_IMPORT_DESCRIPTOR zero = { 0 };
    const IMAGE_IMPORT_DESCRIPTOR* importTable = NULL;
    const IMAGE_IMPORT_BY_NAME* importedFunction;
    const IMAGE_THUNK_DATA32* imageThunkData;

    if (!FindPA(imageSectionHeaders, NumberOfSections, ImportTableVA, &address))
    {
        return;
    }
    importTable = (const IMAGE_IMPORT_DESCRIPTOR*)(Buffer + address);

    int i = 0;
    while (memcmp(importTable + i, &zero, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
    {
        if (!FindPA(imageSectionHeaders, NumberOfSections, importTable[i].Name, &address))
            DLLName = "undef";
        else
            DLLName = (char*)(Buffer + address);

        if (!FindPA(imageSectionHeaders, NumberOfSections, importTable[i].FirstThunk, &address))
        {
            printf("%s,undef\n", DLLName);
            i++;
            continue;
        }
        imageThunkData = (IMAGE_THUNK_DATA32*)(Buffer + address);

        while (imageThunkData->u1.AddressOfData != 0)
        {
            if (IMAGE_ORDINAL_FLAG & imageThunkData->u1.AddressOfData)
            {
                printf("%s,0x%X\n", DLLName, (WORD)imageThunkData->u1.Ordinal);
            }
            else
            {
                if (!FindPA(imageSectionHeaders, NumberOfSections, imageThunkData->u1.AddressOfData, &address))
                {
                    printf("%s,undef\n", DLLName);
                }
                else
                {
                    importedFunction = (const IMAGE_IMPORT_BY_NAME*)(Buffer + address);
                    printf("%s,%s\n", DLLName, importedFunction->Name);
                }
            }
            imageThunkData++;
        }
        i++;
    }
}

void PrintExports(const IMAGE_SECTION_HEADER* imageSectionHeaders, DWORD NumberOfSections, const BYTE* Buffer, DWORD ImportTableVA)
{
    printf("Exports:\n");

    DWORD address, ordIndex;
    const IMAGE_EXPORT_DIRECTORY* exportTable = NULL;
    const DWORD* functions;
    const DWORD* names;
    const WORD* ordinals;

    if (!FindPA(imageSectionHeaders, NumberOfSections, ImportTableVA, &address))
    {
        return;
    }
    exportTable = (const IMAGE_EXPORT_DIRECTORY*)(Buffer + address);

    if (!FindPA(imageSectionHeaders, NumberOfSections, exportTable->AddressOfFunctions, &address))
    {
        return;
    }
    functions = (const DWORD*)(Buffer + address);

    if (!FindPA(imageSectionHeaders, NumberOfSections, exportTable->AddressOfNames, &address))
    {
        return;
    }
    names = (const DWORD*)(Buffer + address);

    if (!FindPA(imageSectionHeaders, NumberOfSections, exportTable->AddressOfNameOrdinals, &address))
    {
        return;
    }
    ordinals = (const WORD*)(Buffer + address);

    for (DWORD i = 0; i < exportTable->NumberOfFunctions; i++)
    {
        ordIndex = FindInArray(ordinals, exportTable->NumberOfNames, i);
        if (ordIndex != -1)
        {
            if (!FindPA(imageSectionHeaders, NumberOfSections, names[ordIndex], &address))
            {
                printf("undef\n");
            }
            else
            {
                printf("%s", (char*)(Buffer + address));
            }
        }

        printf(",0x%X,", i + exportTable->Base);
        if (!FindPA(imageSectionHeaders, NumberOfSections, functions[i], &address))
        {
            printf("undef\n");
        }
        else
        {
            printf("0x%X\n", address);
        }
    }
}