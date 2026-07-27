#include <windows.h>
#include <wchar.h>
#include <stdio.h>

// MinGW wants this
#ifndef CHECKSUM_SUCCESS
#define CHECKSUM_SUCCESS 0
#endif

BOOL verbose = false;

// Typedef for MapFileAndCheckSumW from imagehlp.dll
typedef DWORD (__stdcall *pfnMapFileAndCheckSumW)(
    PCWSTR Filename,
    PDWORD HeaderSum,
    PDWORD CheckSum
);

// Helper function to resolve RVA to File Offset in a PE file
DWORD RvaToOffset(IMAGE_NT_HEADERS64* pNtHeaders, DWORD rva) {
    IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= pSection[i].VirtualAddress && rva < pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) {
            return rva - pSection[i].VirtualAddress + pSection[i].PointerToRawData;
        }
    }
    return 0;
}

// Helper function to find the file offset of an exported function dynamically
DWORD GetExportOffset(LPBYTE pData, const char* szExportName) {
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pData;
    IMAGE_NT_HEADERS64* pNtHeaders = (IMAGE_NT_HEADERS64*)(pData + pDosHeader->e_lfanew);
    DWORD exportDirRva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirRva) return 0;

    DWORD exportDirOffset = RvaToOffset(pNtHeaders, exportDirRva);
    if (!exportDirOffset) return 0;

    IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)(pData + exportDirOffset);
    DWORD* pNames = (DWORD*)(pData + RvaToOffset(pNtHeaders, pExportDir->AddressOfNames));
    WORD* pOrdinals = (WORD*)(pData + RvaToOffset(pNtHeaders, pExportDir->AddressOfNameOrdinals));
    DWORD* pFunctions = (DWORD*)(pData + RvaToOffset(pNtHeaders, pExportDir->AddressOfFunctions));

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        const char* name = (const char*)(pData + RvaToOffset(pNtHeaders, pNames[i]));
        if (strcmp(name, szExportName) == 0) {
            WORD ordinal = pOrdinals[i];
            DWORD funcRva = pFunctions[ordinal];
            return RvaToOffset(pNtHeaders, funcRva);
        }
    }
    return 0;
}

// PE Checksum fixer
BOOL FixPEChecksum(const WCHAR* filePath) {
    HMODULE hLib = LoadLibraryA("imagehlp.dll");
    if (!hLib) return FALSE;

    pfnMapFileAndCheckSumW pMapFn = (pfnMapFileAndCheckSumW)GetProcAddress(hLib, "MapFileAndCheckSumW");
    if (!pMapFn) {
        FreeLibrary(hLib);
        return FALSE;
    }

    DWORD headerSum = 0;
    DWORD calcSum = 0;
    if (pMapFn(filePath, &headerSum, &calcSum) != CHECKSUM_SUCCESS) {
        FreeLibrary(hLib);
        return FALSE;
    }

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        FreeLibrary(hLib);
        return FALSE;
    }

    DWORD bytesRead = 0;
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadFile(hFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hFile);
        FreeLibrary(hLib);
        return FALSE;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        FreeLibrary(hLib);
        return FALSE;
    }

    if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        FreeLibrary(hLib);
        return FALSE;
    }

    IMAGE_NT_HEADERS64 ntHeaders;
    if (!ReadFile(hFile, &ntHeaders, sizeof(IMAGE_NT_HEADERS64), &bytesRead, NULL) || bytesRead != sizeof(IMAGE_NT_HEADERS64)) {
        CloseHandle(hFile);
        FreeLibrary(hLib);
        return FALSE;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        FreeLibrary(hLib);
        return FALSE;
    }

    ntHeaders.OptionalHeader.CheckSum = calcSum;

    if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        FreeLibrary(hLib);
        return FALSE;
    }

    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, &ntHeaders, sizeof(IMAGE_NT_HEADERS64), &bytesWritten, NULL) || bytesWritten != sizeof(IMAGE_NT_HEADERS64)) {
        CloseHandle(hFile);
        FreeLibrary(hLib);
        return FALSE;
    }

    CloseHandle(hFile);
    FreeLibrary(hLib);
    return TRUE;
}

// Wildcard data comparison helper
BOOL CompareData(const BYTE* pData, const BYTE* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask) {
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;
    }
    return (*szMask) == 0;
}

// Signature scanner
DWORD FindPattern(const BYTE* pData, DWORD dwSize, const BYTE* bMask, const char* szMask, DWORD* pMatchCount) {
    DWORD matchOffset = 0;
    *pMatchCount = 0;
    size_t maskLen = strlen(szMask);
    
    for (DWORD i = 0; i < dwSize - maskLen; i++) {
        if (CompareData(&pData[i], bMask, szMask)) {
            matchOffset = i;
            (*pMatchCount)++;
        }
    }
    return matchOffset;
}

// Core patching routine
BOOL PatchKernel(const WCHAR* filePath, BOOL patchKiSet, BOOL patchCpuIdTable, BOOL enableDebug, WCHAR* outMsg, DWORD outMsgLen) {
    HANDLE hFile = CreateFileW(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        swprintf_s(outMsg, outMsgLen, L"Error: Cannot open ntoskrnl.exe. Ensure it is not read-only or in use.");
        return FALSE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize < 5 * 1024 * 1024) {
        swprintf_s(outMsg, outMsgLen, L"Error: Invalid file size. ntoskrnl.exe should be > 5MB.");
        CloseHandle(hFile);
        return FALSE;
    }

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!hMapping) {
        swprintf_s(outMsg, outMsgLen, L"Error: Cannot create file mapping.");
        CloseHandle(hFile);
        return FALSE;
    }

    LPBYTE pData = (LPBYTE)MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!pData) {
        swprintf_s(outMsg, outMsgLen, L"Error: Cannot map file view.");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD kiSetOffset = 0;
    if (patchKiSet) {
        // 1. Scan and Patch KiSetFeatureBits CPU checks
        const BYTE KI_SET_FEATURE_SIG[] = {
            0x3B, 0xC1,
            0x0F, 0x85, 0x00, 0x00, 0x00, 0x00,
            0x41, 0x0F, 0xBA, 0xE6, 0x0B,
            0x0F, 0x83, 0x00, 0x00, 0x00, 0x00,
            0x41, 0x0F, 0xBA, 0xE6, 0x14,
            0x0F, 0x83, 0x00, 0x00, 0x00, 0x00,
            0x41, 0x0F, 0xBA, 0xE5, 0x0D,
            0x0F, 0x83, 0x00, 0x00, 0x00, 0x00
        };
        const char* KI_SET_FEATURE_MASK = "xxxx????xxxxxxx????xxxxxxx????xxxxxxx????";

        DWORD matchCount = 0;
        kiSetOffset = FindPattern(pData, fileSize, KI_SET_FEATURE_SIG, KI_SET_FEATURE_MASK, &matchCount);

        if (matchCount == 0) {
            swprintf_s(outMsg, outMsgLen, L"Error: KiSetFeatureBits CPU check signature not found!\nAborting kernel patch.");
            UnmapViewOfFile(pData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return FALSE;
        }
        if (matchCount > 1) {
            swprintf_s(outMsg, outMsgLen, L"Error: Multiple matches found for KiSetFeatureBits checks!\nAborting for safety.");
            UnmapViewOfFile(pData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return FALSE;
        }

        // NOP out the 4 main hardcoded jumps in KiSetFeatureBits
        memset(pData + kiSetOffset + 2, 0x90, 6);
        memset(pData + kiSetOffset + 13, 0x90, 6);
        memset(pData + kiSetOffset + 24, 0x90, 6);
        memset(pData + kiSetOffset + 35, 0x90, 6);

        // NOP out the 5th and 6th jumps if they match standard offsets
        if (pData[kiSetOffset + 50] == 0x0F && pData[kiSetOffset + 51] == 0x84) {
            memset(pData + kiSetOffset + 50, 0x90, 6);
        }
        if (pData[kiSetOffset + 63] == 0x0F && pData[kiSetOffset + 64] == 0x85) {
            memset(pData + kiSetOffset + 63, 0x90, 6);
        }
    }

    DWORD reqOffset = 0;
    if (patchCpuIdTable) {
        // 2. Scan and Patch CPUID Requirements Table Flags Index 6 (SSE4.2)
        // Entry signature (Leaf=1, Subleaf=0, Mask=0x00100000, Reg=2, Flags=0x0D)
        const BYTE REQ_ENTRY_SIG[20] = {
            0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x10, 0x00,
            0x02, 0x00, 0x00, 0x00,
            0x0D, 0x00, 0x00, 0x00
        };
        const char* REQ_ENTRY_MASK = "xxxxxxxxxxxxxxxxxxxx";

        DWORD reqMatchCount = 0;
        reqOffset = FindPattern(pData, fileSize, REQ_ENTRY_SIG, REQ_ENTRY_MASK, &reqMatchCount);

        if (reqMatchCount == 0) {
            swprintf_s(outMsg, outMsgLen, L"Error: SSE4.2 CPUID requirement table entry not found!\nAborting kernel patch.");
            UnmapViewOfFile(pData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return FALSE;
        }
        if (reqMatchCount > 1) {
            swprintf_s(outMsg, outMsgLen, L"Error: Multiple SSE4.2 CPUID requirement table entries found!\nAborting for safety.");
            UnmapViewOfFile(pData);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return FALSE;
        }

        // Patch Flags byte at offset 16 from 0x0D to 0x0C (bypass check)
        pData[reqOffset + 16] = 0x0C;
    }

    // 3. Optionally patch KeBugCheckEx to EB FE for debugging
    DWORD kbcOffset = GetExportOffset(pData, "KeBugCheckEx");
    if (enableDebug) {
        if (!kbcOffset) {
            swprintf_s(outMsg, outMsgLen, L"Warning: KeBugCheckEx export not found. Proceeding without debugger loop.");
        } else {
            // Overwrite first 2 bytes of KeBugCheckEx with JMP $ (EB FE)
            pData[kbcOffset] = 0xEB;
            pData[kbcOffset + 1] = 0xFE;
        }
    } else {
        // If debug is OFF, make sure we restore standard instructions (48 89) if they were changed
        if (kbcOffset && pData[kbcOffset] == 0xEB && pData[kbcOffset + 1] == 0xFE) {
            pData[kbcOffset] = 0x48;
            pData[kbcOffset + 1] = 0x89;
        }
    }

    // Flush changes and close mapping
    FlushViewOfFile(pData, 0);
    UnmapViewOfFile(pData);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    // 4. Update the PE checksum
    if (!FixPEChecksum(filePath)) {
        swprintf_s(outMsg, outMsgLen, L"Success (modified), but failed to update optional header PE Checksum.");
        return FALSE;
    }
	
    swprintf_s(outMsg, outMsgLen, L"Success! ntoskrnl.exe patched successfully.");
    swprintf_s(outMsg, outMsgLen, L"KiSetFeatureBits: %s (0x%X).\n"
                                  L"CPUID Table: %s (0x%X).\n"
                                  L"KeBugCheckEx Loop: %s.",
                                  patchKiSet ? L"Patched" : L"Skipped", kiSetOffset,
                                  patchCpuIdTable ? L"Patched" : L"Skipped", reqOffset,
                                  enableDebug ? L"Enabled (EB FE)" : L"Disabled");
    return TRUE;
}

static void PrintUsage(const wchar_t* progName) {
    wprintf(L"POP4.2 - Windows 11 SSE4.2 Requirements Patcher \n");
	wprintf(L"Copyright (c) 2026 Lynden Lewis \n\n");
    wprintf(L"Usage:\n");
    wprintf(L"  %ls <path-to-ntoskrnl.exe> [options]\n\n", progName);
	wprintf(L"Options:\n");
	wprintf(L"  -h, --help             Show this help message\n");
    wprintf(L"  --patch-kiset          Patch KiSetFeatureBits CPU checks\n");
    wprintf(L"  --disable-cpuid        Skip patching the CPUID requirements table (patched by default)\n");
    wprintf(L"  --enable-qemu-loop     Enable QEMU/GDB debugging loop (KeBugCheckEx -> EB FE)\n");
}
 
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
 
    const wchar_t* filePath = NULL;
	BOOL patchKiSet = FALSE;
    BOOL patchCpuIdTable = TRUE;
    BOOL enableDebug = FALSE;

    for (int i = 1; i < argc; i++) {
        if (wcscmp(argv[i], L"-h") == 0 || wcscmp(argv[i], L"--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (wcscmp(argv[i], L"--patch-kiset") == 0) {
            patchKiSet = TRUE;
        } else if (wcscmp(argv[i], L"--disable-cpuid") == 0) {
            patchCpuIdTable = FALSE;
        } else if (wcscmp(argv[i], L"--enable-qemu-loop") == 0) {
            enableDebug = TRUE;
        } else if (argv[i][0] == L'-') {
            wprintf(L"Unknown option: %ls\n\n", argv[i]);
            PrintUsage(argv[0]);
            return 1;
        } else {
            if (filePath != NULL) {
                wprintf(L"Error: multiple file paths given ('%ls' and '%ls').\n", filePath, argv[i]);
                return 1;
            }
            filePath = argv[i];
        }
    }
 
    if (filePath == NULL) {
        wprintf(L"ERROR: no target file specified.\n\n");
        PrintUsage(argv[0]);
        return 1;
    }
 
    if (!patchKiSet && !patchCpuIdTable && !enableDebug) {
        wprintf(L"WARNING: No changes were made to ntoskrnl.\n");
        return 1;
    }
 
    wprintf(L"Target: %ls\n\n", filePath);
	wprintf(L"Patched features: \n");
    wprintf(L"  KiSetFeatureBits patch : %ls\n", patchKiSet ? L"yes" : L"no");
    wprintf(L"  CPUID table patch      : %ls\n", patchCpuIdTable ? L"yes" : L"no");
    wprintf(L"  Debug loop             : %ls\n\n", enableDebug ? L"yes" : L"no");
 
    WCHAR statusMsg[512] = L"";
    BOOL ok = PatchKernel(filePath, patchKiSet, patchCpuIdTable, enableDebug, statusMsg, 512);
 
    wprintf(L"%ls\n", statusMsg);
 
    return ok ? 0 : 1;
}