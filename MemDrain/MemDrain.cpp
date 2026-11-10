#include "MemDrain.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

typedef struct {
    const char* option;
    void (*action)(int argc, char* argv[]);
} OptionAction;

BOOL IsAdministrator()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;

    SID_IDENTIFIER_AUTHORITY NtAuthority =
        SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

void help_action(int argc, char* argv[])
{
    printf("use: md.exe <Argument> <Parameter>\n");
    printf("\n  -ws <IM> <-r>   | Drain WorkingSet");
    printf("\n  -sws            | Drain SystemWorkingSet");
    printf("\n  -mpl            | Drain ModifiedPageList");
    printf("\n  -mcl            | Drain CombineMemoryList");
    printf("\n  -sl <0>         | Drain StandbyList");
    printf("\n  -rh             | Drain Registry Hives");
    printf("\n  -all            | Drain All");
    printf("\n  -loop           | Repeat cleanup every 60 seconds");
}

void working_set_action(int argc, char* argv[])
{
    if (argc >= 3)
    {
        DWORD PID = GetPID(argv[2]);

        if (PID == 0)
        {
            printf("Invalid PID.\n");
            return;
        }

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
            FALSE,
            PID
        );

        if (!hProcess)
        {
            printf("OpenProcess failed: %lu\n", GetLastError());
            return;
        }

        if (!EmptyWorkingSet(hProcess))
            printf("EmptyWorkingSet failed: %lu\n", GetLastError());

        if (argc == 4 && strcmp(argv[3], "-r") == 0)
        {
            DWORD ChildPIDs[64] = { 0 };
            DWORD NumProcesses = GetChildProcesses(PID, ChildPIDs);

            for (DWORD i = 0; i < NumProcesses; i++)
            {
                HANDLE hChild = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
                    FALSE,
                    ChildPIDs[i]
                );

                if (hChild)
                {
                    EmptyWorkingSet(hChild);
                    CloseHandle(hChild);
                }
            }
        }

        CloseHandle(hProcess);
        printf("Finished.\n");
        return;
    }

    EnablePrivilege(
        GetCurrentProcessId(),
        SE_PROF_SINGLE_PROCESS_NAME
    );

    SYSTEM_MEMORY_LIST_COMMAND ws = MemoryEmptyWorkingSets;

    NtSetSystemInformation(
        SystemMemoryListInformation,
        &ws,
        sizeof(ws)
    );

    printf("Finished.\n");
}

void system_working_set_action(int argc, char* argv[])
{
    EnablePrivilege(
        GetCurrentProcessId(),
        SE_INCREASE_QUOTA_NAME
    );

    SYSTEM_FILECACHE_INFORMATION sfi = { 0 };

    sfi.Flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE;
    sfi.MaximumWorkingSet = (SIZE_T)-1;
    sfi.MinimumWorkingSet = (SIZE_T)-1;

    NtSetSystemInformation(
        SystemFileCacheInformationEx,
        &sfi,
        sizeof(sfi)
    );

    printf("Finished.\n");
}

void modified_page_list_action(int argc, char* argv[])
{
    EnablePrivilege(
        GetCurrentProcessId(),
        SE_PROF_SINGLE_PROCESS_NAME
    );

    SYSTEM_MEMORY_LIST_COMMAND mpl = MemoryFlushModifiedList;

    NtSetSystemInformation(
        SystemMemoryListInformation,
        &mpl,
        sizeof(mpl)
    );

    printf("Finished.\n");
}

void combine_memory_list_action(int argc, char* argv[])
{
    EnablePrivilege(
        GetCurrentProcessId(),
        SE_PROF_SINGLE_PROCESS_NAME
    );

    MEMORY_COMBINE_INFORMATION_EX mcl = { 0 };

    mcl.Handle = NULL;
    mcl.Flags = 0;
    mcl.PagesCombined = 0;

    NtSetSystemInformation(
        SystemCombinePhysicalMemoryInformation,
        &mcl,
        sizeof(mcl)
    );

    printf("Finished.\n");
}

void stanby_list_action(int argc, char* argv[])
{
    EnablePrivilege(
        GetCurrentProcessId(),
        SE_PROF_SINGLE_PROCESS_NAME
    );

    SYSTEM_MEMORY_LIST_COMMAND sl = MemoryPurgeStandbyList;

    NtSetSystemInformation(
        SystemMemoryListInformation,
        &sl,
        sizeof(sl)
    );

    if (argc > 2)
    {
        SYSTEM_MEMORY_LIST_COMMAND sl0 =
            MemoryPurgeLowPriorityStandbyList;

        NtSetSystemInformation(
            SystemMemoryListInformation,
            &sl0,
            sizeof(sl0)
        );
    }

    printf("Finished.\n");
}

void registry_hives_action(int argc, char* argv[])
{
    NtSetSystemInformation(
        SystemRegistryReconciliationInformation,
        NULL,
        0
    );

    printf("Finished.\n");
}

void all_action(int argc, char* argv[])
{
    EnablePrivilege(
        GetCurrentProcessId(),
        SE_PROF_SINGLE_PROCESS_NAME
    );

    EnablePrivilege(
        GetCurrentProcessId(),
        SE_INCREASE_QUOTA_NAME
    );

    SYSTEM_MEMORY_LIST_COMMAND ws = MemoryEmptyWorkingSets;

    NtSetSystemInformation(
        SystemMemoryListInformation,
        &ws,
        sizeof(ws)
    );

    SYSTEM_FILECACHE_INFORMATION sfi = { 0 };

    sfi.Flags = QUOTA_LIMITS_HARDWS_MIN_DISABLE;
    sfi.MaximumWorkingSet = (SIZE_T)-1;
    sfi.MinimumWorkingSet = (SIZE_T)-1;

    NtSetSystemInformation(
        SystemFileCacheInformationEx,
        &sfi,
        sizeof(sfi)
    );

    SYSTEM_MEMORY_LIST_COMMAND mpl = MemoryFlushModifiedList;

    NtSetSystemInformation(
        SystemMemoryListInformation,
        &mpl,
        sizeof(mpl)
    );

    MEMORY_COMBINE_INFORMATION_EX mcl = { 0 };

    NtSetSystemInformation(
        SystemCombinePhysicalMemoryInformation,
        &mcl,
        sizeof(mcl)
    );

    SYSTEM_MEMORY_LIST_COMMAND sl = MemoryPurgeStandbyList;

    NtSetSystemInformation(
        SystemMemoryListInformation,
        &sl,
        sizeof(sl)
    );

    SYSTEM_MEMORY_LIST_COMMAND sl0 =
        MemoryPurgeLowPriorityStandbyList;

    NtSetSystemInformation(
        SystemMemoryListInformation,
        &sl0,
        sizeof(sl0)
    );

    NtSetSystemInformation(
        SystemRegistryReconciliationInformation,
        NULL,
        0
    );

    printf("Finished.\n");
}

// User-controlled periodic execution.
// Runs the selected cleanup operation every 60 seconds.
void loop_action(int argc, char* argv[])
{
    if (argc < 3)
    {
        printf("Usage: md.exe -loop -all\n");
        printf("Usage: md.exe -loop -ws\n");
        printf("Press CTRL+C to stop.\n");
        return;
    }

    printf("MemDrain periodic mode: 60 seconds.\n");
    printf("Press CTRL+C to stop.\n");

    while (TRUE)
    {
        printf("\n[MemDrain] Starting cleanup...\n");

        if (strcmp(argv[2], "-all") == 0)
        {
            all_action(argc, argv);
        }
        else if (strcmp(argv[2], "-ws") == 0)
        {
            working_set_action(argc - 1, argv + 1);
        }
        else
        {
            printf("Unsupported periodic operation.\n");
            return;
        }

        printf("[MemDrain] Next run in 60 seconds.\n");

        Sleep(60000);
    }
}

OptionAction option_actions[] =
{
    { "help", help_action },
    { "-ws", working_set_action },
    { "-sws", system_working_set_action },
    { "-mpl", modified_page_list_action },
    { "-mcl", combine_memory_list_action },
    { "-sl", stanby_list_action },
    { "-rh", registry_hives_action },
    { "-all", all_action },
    { "-loop", loop_action },
    { NULL, NULL }
};

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        help_action(argc, argv);
        return 0;
    }

    if (!IsAdministrator())
    {
        printf("[WARNING] Not running as Administrator.\n");
        printf("Some memory operations may fail.\n\n");
    }

    for (int i = 0; option_actions[i].option != NULL; i++)
    {
        if (strcmp(argv[1], option_actions[i].option) == 0)
        {
            option_actions[i].action(argc, argv);
            return 0;
        }
    }

    help_action(argc, argv);
    return 0;
}
