#pragma once

typedef struct _PE_SECTIONS
{
    char* Name;
    DWORD FileAddress;
    DWORD Size;
}PE_SECTIONS, *PPE_SECTIONS;

typedef struct _PE_DATA
{
    WORD Machine;
    WORD NumberOfSections;
    WORD Characteristics;
    DWORD AddressOfEntryPoint;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD Subsystem;
    DWORD NumberOfRvaAndSizes;
    PE_SECTIONS* Sections;
}PE_DATA, *PPE_DATA;

void PrintData(PE_DATA* Data);