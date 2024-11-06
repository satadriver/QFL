


#pragma once

#include <Windows.h>



#define CODE_BREAKPOINT			0
#define DATA_W_BREAKPOINT		1
#define IO_BREAKPOINT			2
#define DATA_RW_BREAKPOINT		3




int SetHardBreakPoint(int pid, const char* dll, const char* fun);

int SetHardBreakPoint(int pid, LPVOID addr, int rw, int size);

int HardBreakPoint(HANDLE ht, PVOID pAddress, int rw, int size);