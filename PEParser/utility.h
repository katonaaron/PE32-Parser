#pragma once

DWORD ConvertRVAToFa(DWORD SectionPA, DWORD SectionVA, DWORD VA);
BOOL IsInSection(DWORD SectionVA, DWORD SectionSize, DWORD VA);
BOOL FindPA(const IMAGE_SECTION_HEADER* imageSectionHeaders, DWORD NumberOfSections, DWORD VA, DWORD* PA);
DWORD FindInArray(const WORD* Array, DWORD Size, DWORD Value);

int MapPEFile(const char* FilePath, HANDLE* FileHandle, HANDLE* MappingHandle, BYTE** Buffer);
void UnmapPEFile(HANDLE FileHandle, HANDLE MappingHandle);