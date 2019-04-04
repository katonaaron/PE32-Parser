#include "pch.h"
#include "error.h"

void PrintError(DWORD Code, ...)
{
    va_list argptr;
    char* functionName;

    switch (Code)
    {
    case PE_INVALID_FILE:
        printf_s("error: The file is not a valid PE 32bit file\n");
        break;
    case PE_NO_INPUT_FILE:
        printf_s("error: A path to a PE file is required\n");
        break;
    case PE_NO_MEMORY:
        printf_s("error: Memory allocation failed\n");
        break;
    case PE_INVALID_PARAMETER:
        va_start(argptr, Code);
        functionName = va_arg(argptr, char*);
        va_end(argptr);

        printf_s("error: Invalid parameter was given for \"%s\"\n", functionName);
        break;
    default:
        va_start(argptr, Code);
        functionName = va_arg(argptr, char*);
        va_end(argptr);

        if (functionName)
            printf_s("error: \"%s\" failed with error code: 0x%x\n", functionName, Code);
        else
            printf_s("error: Invalid parameter for PrintError\n");
        break;
    }
}