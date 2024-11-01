#pragma once

#include <windows.h>



#define MAX_TRAMP_SIZE					64
#define TRAMP_BAR_LIMIT					64

#pragma pack(1)

typedef struct  
{
	unsigned char* oldaddr;
	char len;
}REPLACE_CODE;

typedef struct  _HOOK_TRAMPS
{
	_HOOK_TRAMPS * prev;
	_HOOK_TRAMPS * next;
	int valid;
	WCHAR apiName[32];

	BYTE code[MAX_TRAMP_SIZE];

	BYTE oldcode[MAX_TRAMP_SIZE];
	REPLACE_CODE replace;

}HOOK_TRAMPS;

#pragma pack()


HOOK_TRAMPS* searchTrump(const WCHAR* funcname);

int deleteTrump(const WCHAR* funcname);

HOOK_TRAMPS* addTrump(const WCHAR* funcname);

extern "C" __declspec(dllexport) int hook(const WCHAR* modulename,const WCHAR* funcname, BYTE * newfuncaddr, PROC* keepaddr);

extern "C" __declspec(dllexport) int inlinehook64(BYTE * newfun, BYTE * oldfun, PROC* keepaddr, const WCHAR * funcname);

extern "C" __declspec(dllexport) int inlinehook32(BYTE * newfun, BYTE * oldfun, PROC* keepaddr, const WCHAR * funcname);

int unhook(CONST WCHAR* modulename, const WCHAR* wstrfuncname);

int  unhookall();
