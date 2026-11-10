#pragma once

#include "MemDrain.h"

/* Help text is kept in its own header as requested. */
static inline void help_action(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    MD_PRINT("use: md.exe <Argument> <Parameter>\n");
    MD_PRINT("\n  -ws <process.exe> <-r> | Drain WorkingSet");
    MD_PRINT("\n  -sws                   | Drain SystemWorkingSet");
    MD_PRINT("\n  -mpl                   | Drain ModifiedPageList");
    MD_PRINT("\n  -mcl                   | Drain CombineMemoryList");
    MD_PRINT("\n  -sl [0]                | Drain StandbyList (0 = low priority)");
    MD_PRINT("\n  -rh                    | Drain Registry Hives");
    MD_PRINT("\n  -all                   | Drain All");
    MD_PRINT("\n  -loop                  | Repeat -all every 1 second (silent)");
    MD_PRINT("\n  -silent                | Suppress program output");
    MD_PRINT("\n  -install               | Install silent SYSTEM startup task");
    MD_PRINT("\n  -uninstall             | Stop and remove startup task\n");
}
