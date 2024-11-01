#pragma once

#include <Windows.h>
#include <iostream>

using namespace std;


#define OffsetOf(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER )


typedef int (*ptrfunction)(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8,
    int p9, int p10, int p11, int p12, int p13, int p14, int p15, int p16);

int ExecFunction(char* szfunc);

int GetProcess(const char* pn);

int IsProc64Bit(HANDLE h);

int Is64Bit();

BOOL PsKillProcess(const char* KillProcessName);

int GetProcess(const char* pn);

string GetCurPath();

VOID ElevationPrivilege();

HMODULE GetProcModule(DWORD pid, CONST CHAR* moduleName);

LPVOID GetProcessAddress(int pid, const char* dll, const char* fun);

LPVOID GetAlignAddress(LPVOID addr);

int GetAddressBoundary(LPVOID addr, SIZE_T size, LPVOID* start, LPVOID* end);

int ProcMemProtect(HANDLE hp, LPVOID addr, SIZE_T size, int v);

string GetNameFromPid(int pid);
