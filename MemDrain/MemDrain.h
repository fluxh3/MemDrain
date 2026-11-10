#pragma once

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <string.h>
#include <wchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

/* Defined in MemDrain.cpp. All original/header messages respect -silent. */
extern bool g_silent;

#define MD_PRINT(...) do { if (!g_silent) printf(__VA_ARGS__); } while (0)

typedef struct _MEMORY_COMBINE_INFORMATION_EX {
    HANDLE Handle;
    ULONG_PTR PagesCombined;
    ULONG Flags;
} MEMORY_COMBINE_INFORMATION_EX, *PMEMORY_COMBINE_INFORMATION_EX;

typedef struct _SYSTEM_FILECACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
    MemoryCaptureAccessedBits,
    MemoryCaptureAndResetAccessedBits,
    MemoryEmptyWorkingSets,
    MemoryFlushModifiedList,
    MemoryPurgeStandbyList,
    MemoryPurgeLowPriorityStandbyList,
    MemoryCommandMax
} SYSTEM_MEMORY_LIST_COMMAND;

typedef enum _SYSTEM_INFORMATION_CLASS_MOD {
    SystemCombinePhysicalMemoryInformation = 130,
    SystemFileCacheInformationEx = 81,
    SystemMemoryListInformation = 80,
    SystemRegistryReconciliationInformation = 155,
} SYSTEM_INFORMATION_CLASS_MOD;

#ifdef __cplusplus
extern "C" {
#endif

/* NtSetSystemInformation is exported by ntdll.dll. */
NTSYSAPI NTSTATUS NTAPI NtSetSystemInformation(
    SYSTEM_INFORMATION_CLASS_MOD SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
);

#ifdef __cplusplus
}
#endif

/*
 * Process enumeration uses the explicit wide-character Toolhelp APIs.
 * Some MinGW distributions expose the W declarations but not the A aliases
 * under the project's current Unicode/header configuration.
 */

/* Original helper: returns direct child processes, up to 64. */
static inline DWORD GetChildProcesses(DWORD ParentPID, DWORD* ChildPIDs)
{
    if (ChildPIDs == NULL)
        return 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        MD_PRINT("Error creating process snapshot.\n");
        return 0;
    }

    PROCESSENTRY32W pe32;
    ZeroMemory(&pe32, sizeof(pe32));
    pe32.dwSize = sizeof(pe32);

    DWORD NumProcesses = 0;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ParentProcessID == ParentPID) {
                if (NumProcesses < 64) {
                    ChildPIDs[NumProcesses++] = pe32.th32ProcessID;
                } else {
                    MD_PRINT("Maximum child-process limit reached.\n");
                    break;
                }
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return NumProcesses;
}

/* Original helper: resolves an ANSI executable name to its first matching PID. */
static inline DWORD GetPID(const char* processName)
{
    if (processName == NULL || *processName == '\0')
        return 0;

    /* argv is narrow text in this program; convert it using the active code page. */
    wchar_t wideProcessName[MAX_PATH];
    int converted = MultiByteToWideChar(
        CP_ACP,
        0,
        processName,
        -1,
        wideProcessName,
        (int)(sizeof(wideProcessName) / sizeof(wideProcessName[0]))
    );

    if (converted == 0)
        return 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        MD_PRINT("Error creating process snapshot.\n");
        return 0;
    }

    PROCESSENTRY32W entry;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        MD_PRINT("Error reading the first process entry.\n");
        return 0;
    }

    DWORD processId = 0;
    do {
        if (_wcsicmp(entry.szExeFile, wideProcessName) == 0) {
            processId = entry.th32ProcessID;
            break;
        }
    } while (Process32NextW(snapshot, &entry));

    CloseHandle(snapshot);
    return processId;
}

/* Original privilege helper; output is suppressed when -silent is active. */
static inline bool EnablePrivilege(
    DWORD processId,
    LPCSTR privilegeName,
    HANDLE hProcess = NULL)
{
    TOKEN_PRIVILEGES tp;
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValueA(NULL, privilegeName,
                               &tp.Privileges[0].Luid)) {
        MD_PRINT("Error looking up privilege value.\n");
        return false;
    }

    bool openedProcessHere = false;
    if (hProcess == NULL) {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess == NULL) {
            MD_PRINT("Error opening process for token access.\n");
            return false;
        }
        openedProcessHere = true;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess,
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        MD_PRINT("Error opening process token.\n");
        if (openedProcessHere)
            CloseHandle(hProcess);
        return false;
    }

    SetLastError(ERROR_SUCCESS);
    BOOL adjusted = AdjustTokenPrivileges(
        hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD adjustError = GetLastError();

    CloseHandle(hToken);
    if (openedProcessHere)
        CloseHandle(hProcess);

    if (!adjusted || adjustError == ERROR_NOT_ALL_ASSIGNED) {
        MD_PRINT("Error adjusting token privileges.\n");
        return false;
    }

    return true;
}

