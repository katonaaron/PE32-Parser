#include "pch.h"
#include "data.h"

void PrintData(PE_DATA* Data)
{
    if (Data)
    {
        printf("File Header:\n");
        printf("-Machine:0x%X\n", Data->Machine);
        printf("-NumberOfSections:0x%X\n", Data->NumberOfSections);
        printf("-Characteristics:0x%X\n", Data->Characteristics);

        printf("Optional Header:\n");
        printf("-AddressOfEntryPoint:0x%X\n", Data->AddressOfEntryPoint);
        printf("-ImageBase:0x%X\n", Data->ImageBase);
        printf("-SectionAlignment:0x%X\n", Data->SectionAlignment);
        printf("-FileAlignment:0x%X\n", Data->FileAlignment);
        printf("-Subsystem:0x%X\n", Data->Subsystem);
        printf("-NumberOfRvaAndSizes:0x%X\n", Data->NumberOfRvaAndSizes);


        printf("Sections:\n");
        for (int i = 0; i < Data->NumberOfSections; i++)
        {
            printf("%.8s,0x%X,0x%X\n", Data->Sections[i].Name, Data->Sections[i].FileAddress, Data->Sections[i].Size);
        }
    }
}