#pragma once

#define MAKE_ERROR_CODE(Severity, ErrorValue) ((Severity << 30) + ErrorValue)

#define PE_ERROR_SEVERITY 0x1

#define PE_INVALID_FILE MAKE_ERROR_CODE(PE_ERROR_SEVERITY, 0x1)
#define PE_NO_INPUT_FILE MAKE_ERROR_CODE(PE_ERROR_SEVERITY, 0x2)
#define PE_INVALID_PARAMETER MAKE_ERROR_CODE(PE_ERROR_SEVERITY, 0x3)
#define PE_NO_MEMORY MAKE_ERROR_CODE(PE_ERROR_SEVERITY, 0x4)

void PrintError(DWORD Code, ...);