# MemDrain
[![Total Downloads](https://img.shields.io/github/downloads/LuSlower/MemDrain/total.svg)](https://github.com/LuSlower/MemDrain/releases)

```
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
```

small CLI to drain memory from different lists and sets
> [!CAUTION]
> I am neither for nor against "memory optimizers", this was only made for learning purposes so use it and enjoy it
> 
> If you want to really see what it does without any knowledge, you can read [this article](https://www.itprotoday.com/cloud-computing/memory-optimization-hoax)
