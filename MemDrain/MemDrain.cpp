#include "MemDrain.h"
#include "helpmem.h"

#include <stdio.h>
#include <string.h>

bool g_silent = false;

#define MEMDRAIN_TASK_NAME "MemDrain - Startup Memory Cleanup"
#define MEMDRAIN_LOOP_DELAY_MS 1000


typedef struct {
    const char* option;
    void (*action)(int argc, char* argv[]);
} OptionAction;


/* ---------------------------------------------------------
   Original memory-cleanup actions
   --------------------------------------------------------- */

void working_set_action(int argc, char* argv[])
{
    if (argc >= 3 && strcmp(argv[2], "-silent") != 0) {
        DWORD PID = GetPID(argv[2]);
        if (PID == 0) {
            MD_PRINT("Invalid process name or PID.\n");
            return;
        }

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
            FALSE,
            PID
        );

        if (hProcess == NULL) {
            MD_PRINT("OpenProcess failed: %lu\n", GetLastError());
            return;
        }

        if (!EmptyWorkingSet(hProcess))
            MD_PRINT("EmptyWorkingSet failed: %lu\n", GetLastError());

        if (argc >= 4 && strcmp(argv[3], "-r") == 0) {
            DWORD ChildPIDs[64] = { 0 };
            DWORD NumProcesses = GetChildProcesses(PID, ChildPIDs);

            for (DWORD i = 0; i < NumProcesses; i++) {
                HANDLE hChild = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
                    FALSE,
                    ChildPIDs[i]
                );

                if (hChild != NULL) {
                    if (!EmptyWorkingSet(hChild))
                        MD_PRINT("EmptyWorkingSet failed for child %lu: %lu\n",
                                 ChildPIDs[i], GetLastError());
                    CloseHandle(hChild);
                }
            }
        }

        CloseHandle(hProcess);
        MD_PRINT("Success\n");
        return;
    }

    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    SYSTEM_MEMORY_LIST_COMMAND ws = MemoryEmptyWorkingSets;
    NtSetSystemInformation(
        SystemMemoryListInformation,
        &ws,
        sizeof(ws)
    );

    MD_PRINT("Success\n");
}

void system_working_set_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    EnablePrivilege(GetCurrentProcessId(), SE_INCREASE_QUOTA_NAME);

    SYSTEM_FILECACHE_INFORMATION sfi;
    SecureZeroMemory(&sfi, sizeof(sfi));
    sfi.Flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE;
    sfi.MaximumWorkingSet = (SIZE_T)-1;
    sfi.MinimumWorkingSet = (SIZE_T)-1;

    NtSetSystemInformation(
        SystemFileCacheInformationEx,
        &sfi,
        sizeof(sfi)
    );

    MD_PRINT("Success\n");
}

void modified_page_list_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    SYSTEM_MEMORY_LIST_COMMAND mpl = MemoryFlushModifiedList;
    NtSetSystemInformation(
        SystemMemoryListInformation,
        &mpl,
        sizeof(mpl)
    );

    MD_PRINT("Success\n");
}

void combine_memory_list_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    MEMORY_COMBINE_INFORMATION_EX mcl;
    SecureZeroMemory(&mcl, sizeof(mcl));
    mcl.Handle = NULL;
    mcl.Flags = 0;
    mcl.PagesCombined = 0;

    NtSetSystemInformation(
        SystemCombinePhysicalMemoryInformation,
        &mcl,
        sizeof(mcl)
    );

    MD_PRINT("Success\n");
}

void stanby_list_action(int argc, char* argv[])
{
    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);

    SYSTEM_MEMORY_LIST_COMMAND sl = MemoryPurgeStandbyList;
    NtSetSystemInformation(
        SystemMemoryListInformation,
        &sl,
        sizeof(sl)
    );

    if (argc > 2 && strcmp(argv[2], "-silent") != 0) {
        SYSTEM_MEMORY_LIST_COMMAND sl0 = MemoryPurgeLowPriorityStandbyList;
        NtSetSystemInformation(
            SystemMemoryListInformation,
            &sl0,
            sizeof(sl0)
        );
    }

    MD_PRINT("Success\n");
}

void registry_hives_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    NtSetSystemInformation(
        SystemRegistryReconciliationInformation,
        NULL,
        0
    );

    MD_PRINT("Success\n");
}

void all_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    EnablePrivilege(GetCurrentProcessId(), SE_PROF_SINGLE_PROCESS_NAME);
    EnablePrivilege(GetCurrentProcessId(), SE_INCREASE_QUOTA_NAME);

    SYSTEM_MEMORY_LIST_COMMAND ws = MemoryEmptyWorkingSets;
    NtSetSystemInformation(SystemMemoryListInformation, &ws, sizeof(ws));

    SYSTEM_FILECACHE_INFORMATION sfi;
    SecureZeroMemory(&sfi, sizeof(sfi));
    sfi.Flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE;
    sfi.MaximumWorkingSet = (SIZE_T)-1;
    sfi.MinimumWorkingSet = (SIZE_T)-1;
    NtSetSystemInformation(SystemFileCacheInformationEx, &sfi, sizeof(sfi));

    SYSTEM_MEMORY_LIST_COMMAND mpl = MemoryFlushModifiedList;
    NtSetSystemInformation(SystemMemoryListInformation, &mpl, sizeof(mpl));

    MEMORY_COMBINE_INFORMATION_EX mcl;
    SecureZeroMemory(&mcl, sizeof(mcl));
    mcl.Handle = NULL;
    mcl.Flags = 0;
    mcl.PagesCombined = 0;
    NtSetSystemInformation(
        SystemCombinePhysicalMemoryInformation,
        &mcl,
        sizeof(mcl)
    );

    SYSTEM_MEMORY_LIST_COMMAND sl = MemoryPurgeStandbyList;
    NtSetSystemInformation(SystemMemoryListInformation, &sl, sizeof(sl));

    SYSTEM_MEMORY_LIST_COMMAND sl0 = MemoryPurgeLowPriorityStandbyList;
    NtSetSystemInformation(SystemMemoryListInformation, &sl0, sizeof(sl0));

    NtSetSystemInformation(SystemRegistryReconciliationInformation, NULL, 0);

    MD_PRINT("Success\n");
}


/* ---------------------------------------------------------
   One-second loop

   Each pass targets a one-second start-to-start interval.
   If cleanup takes longer than one second, the next pass
   starts immediately after it finishes; passes never overlap.
   --------------------------------------------------------- */

void loop_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    /* Loop mode is always quiet, including native helper messages. */
    g_silent = true;

    for (;;) {
        DWORD cycleStart = GetTickCount();
        all_action(0, NULL);

        DWORD elapsed = GetTickCount() - cycleStart;
        if (elapsed < MEMDRAIN_LOOP_DELAY_MS) {
            Sleep(MEMDRAIN_LOOP_DELAY_MS - elapsed);
        }
    }
}


/* ---------------------------------------------------------
   Scheduled Task helpers
   --------------------------------------------------------- */

static BOOL IsAdministrator(void)
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(
            &authority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &adminGroup)) {
        return FALSE;
    }

    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);
    return isAdmin;
}

static BOOL RunSchtasks(const char* arguments)
{
    char systemDirectory[MAX_PATH];
    char schtasksPath[MAX_PATH];
    char commandLine[8192];

    UINT length = GetSystemDirectoryA(systemDirectory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        MD_PRINT("Could not locate the Windows system directory.\n");
        return FALSE;
    }

    if (snprintf(schtasksPath, sizeof(schtasksPath),
                 "%s\\schtasks.exe", systemDirectory) < 0) {
        return FALSE;
    }

    if (snprintf(commandLine, sizeof(commandLine),
                 "\"%s\" %s", schtasksPath, arguments) < 0) {
        return FALSE;
    }

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    BOOL created = CreateProcessA(
        schtasksPath,
        commandLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &startupInfo,
        &processInfo
    );

    if (!created) {
        MD_PRINT("Could not start schtasks.exe: %lu\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode = 1;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    return exitCode == 0;
}

static void install_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    if (!IsAdministrator()) {
        MD_PRINT("Run MemDrain as Administrator to install the startup task.\n");
        return;
    }

    char executablePath[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, executablePath, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        MD_PRINT("Could not determine MemDrain.exe path: %lu\n", GetLastError());
        return;
    }

    char arguments[8192];
    int written = snprintf(
        arguments,
        sizeof(arguments),
        "/Create /TN \"%s\" /SC ONSTART /RU SYSTEM /RL HIGHEST "
        "/TR \"\\\"%s\\\" -loop -silent\" /F",
        MEMDRAIN_TASK_NAME,
        executablePath
    );

    if (written < 0 || (size_t)written >= sizeof(arguments)) {
        MD_PRINT("Scheduled Task command is too long.\n");
        return;
    }

    if (!RunSchtasks(arguments)) {
        MD_PRINT("Scheduled Task installation failed.\n");
        return;
    }

    MD_PRINT("Startup task installed. Starting the task now.\n");

    char runArguments[512];
    snprintf(runArguments, sizeof(runArguments),
             "/Run /TN \"%s\"", MEMDRAIN_TASK_NAME);
    if (!RunSchtasks(runArguments))
        MD_PRINT("Task was installed, but could not be started immediately.\n");
}

static void uninstall_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    if (!IsAdministrator()) {
        MD_PRINT("Run MemDrain as Administrator to remove the startup task.\n");
        return;
    }

    char arguments[512];
    snprintf(arguments, sizeof(arguments),
             "/End /TN \"%s\"", MEMDRAIN_TASK_NAME);
    RunSchtasks(arguments); /* It may not be running; continue to delete. */

    snprintf(arguments, sizeof(arguments),
             "/Delete /TN \"%s\" /F", MEMDRAIN_TASK_NAME);

    if (RunSchtasks(arguments))
        MD_PRINT("Startup task removed.\n");
    else
        MD_PRINT("Could not remove the startup task.\n");
}


/* ---------------------------------------------------------
   Original option-action dispatch table plus additions
   --------------------------------------------------------- */

OptionAction option_actions[] = {
    { "help", help_action },
    { "-help", help_action },
    { "/?", help_action },
    { "-ws", working_set_action },
    { "-sws", system_working_set_action },
    { "-mpl", modified_page_list_action },
    { "-mcl", combine_memory_list_action },
    { "-sl", stanby_list_action },
    { "-rh", registry_hives_action },
    { "-all", all_action },
    { "-loop", loop_action },
    { "-install", install_action },
    { "-uninstall", uninstall_action },
    { NULL, NULL }
};


int main(int argc, char* argv[])
{
    if (argc < 2) {
        help_action(argc, argv);
        return 0;
    }

    /* Accept -silent anywhere in the argument list. */
    for (int i = 1; i < argc; ++i) {
        if (_stricmp(argv[i], "-silent") == 0 ||
            _stricmp(argv[i], "--silent") == 0) {
            g_silent = true;
        }
    }

    for (int i = 0; option_actions[i].option != NULL; ++i) {
        if (_stricmp(argv[1], option_actions[i].option) == 0) {
            option_actions[i].action(argc, argv);
            return 0;
        }
    }

    help_action(argc, argv);
    return 0;
}
