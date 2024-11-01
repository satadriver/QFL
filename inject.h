#pragma once


#include <winddi.h>

int RemoteInject(int pid);

int inject(int pid,char * szfunc);

typedef BOOL(__stdcall* ProcDllMain)(HINSTANCE, DWORD, LPVOID);

typedef INT(__stdcall* ProcMain)(int ,char **);

typedef BOOL(__stdcall* ProcWinMain)(HINSTANCE, HINSTANCE, DWORD, LPVOID);