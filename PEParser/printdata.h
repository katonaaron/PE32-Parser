#pragma once
#include "utility.h"

void PrintFileHeader(const IMAGE_FILE_HEADER* ImageFileHeader);
void PrintOptionalHeader(
    const IMAGE_OPTIONAL_HEADER32* ImageOptionalHeader,
    const IMAGE_SECTION_HEADER* ImageSectionHeaders,
    WORD NumberOfSections
);
void PrintSections(const IMAGE_SECTION_HEADER* ImageSectionHeaders, WORD NumberOfSections);
void PrintImports(const IMAGE_SECTION_HEADER* imageSectionHeaders, DWORD NumberOfSections, const BYTE* Buffer, DWORD ImportTableVA);
void PrintExports(const IMAGE_SECTION_HEADER* imageSectionHeaders, DWORD NumberOfSections, const BYTE* Buffer, DWORD ImportTableVA);