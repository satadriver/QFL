#pragma once
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include "log.h"
#include "utils.h"

#include "debug.h"
#include "breakPoint.h"
#include "hwBreakPoint.h"
#include "list.h"


//rw=0:code
//rw=1:write
//rw=2:io
//rw=3:read write
//size:8,4,2,1
int HardBreakPoint(HANDLE ht, PVOID pAddress, int rw, int size)
{
	int ret = 0;
	CONTEXT context;

	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	ret = GetThreadContext(ht, &context);

	int mask = 0;
	int num = 0;
	for (int i = 1; i <= 64; i = i * 4) {
		if ((i & context.Dr7) == 0) {
			mask = i;
			break;
		}
		num++;
	}
	if (mask == 0) {
		return 0;
	}
	int len = 0;
	if (size == 4) {
		len = 3;
	}
	else if (size == 2) {
		len = 1;
	}
	else if (size == 1) {
		len = 0;
	}
	else if (size == 8) {
		len = 2;
	}
	DWORD v = ((len << 2) | rw) << (16 + num * 4);

	DWORD reverse = 0xf << (16 + num * 4);

	if (num == 0) {
		context.Dr0 = (DWORD)pAddress;
	}
	else if (num == 1) {
		context.Dr1 = (DWORD)pAddress;
	}
	else if (num == 2) {
		context.Dr2 = (DWORD)pAddress;
	}
	else if (num == 3) {
		context.Dr3 = (DWORD)pAddress;
	}

	context.Dr7 &= (~reverse);	//执行断点（16、17位 置0） 1字节（18、19位 置0）
	context.Dr7 |= v;

	context.Dr7 |= mask;

	ret = SetThreadContext(ht, &context);
	return TRUE;
}









int SetHardBreakPoint(int pid, LPVOID addr, int rw, int size) {
	int cnt = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hSnap, &te))
		{
			do
			{
				if (te.th32OwnerProcessID == pid)
				{
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
					if (hThread) {
						HardBreakPoint(hThread, addr, rw, size);
						CloseHandle(hThread);
						cnt++;
					}

				}
			} while (Thread32Next(hSnap, &te));
		}
	}

	CloseHandle(hSnap);
	return cnt;
}





int SetHardBreakPoint(int pid, const char* dll, const char* fun) {
	int cnt = 0;
	HMODULE hm = GetProcModule(pid, dll);
	if (hm) {
		char* lpfunc = (char*)GetProcAddress(hm, fun);

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 te;
			te.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hSnap, &te))
			{
				do
				{
					if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
						if (hThread) {
							HardBreakPoint(hThread, lpfunc, CODE_BREAKPOINT, 1);
							CloseHandle(hThread);
							cnt++;
						}

					}
				} while (Thread32Next(hSnap, &te));
			}
		}

		CloseHandle(hSnap);
	}

	return cnt;
}
