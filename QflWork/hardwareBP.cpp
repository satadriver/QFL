
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include "log.h"
#include "utils.h"
#include <winsock.h>

#include "hardwarebp.h"
#include "network.h"
#include "breakPoint.h"

HardwareBP * HardwareBP::m_instance = new HardwareBP();


HardwareBP::HardwareBP() {

	HMODULE hm = GetModuleHandleA("ws2_32.dll");
	if (hm) {
		m_recv = (LPVOID)GetProcAddress(hm, "recv");
		m_recvfrom = (LPVOID)GetProcAddress(hm, "recvfrom");
		m_WSARecv = (LPVOID)GetProcAddress(hm, "WSARecv");
		m_WSARecvFrom = (LPVOID)GetProcAddress(hm, "WSARecvFrom");
	}
}


HardwareBP::~HardwareBP() {

}


LONG HardwareBP::PvectoredExceptionHandler(_EXCEPTION_POINTERS* expInfo)
{
	printf("hello\r\n");
	unsigned char code = *(unsigned char*)((char*)expInfo->ExceptionRecord->ExceptionAddress - 1);
	if (code == 0xcc) {

	}
	else if (expInfo->ExceptionRecord->ExceptionAddress == m_instance->m_recv)
	{

	}
	else if (expInfo->ExceptionRecord->ExceptionAddress == m_instance->m_recvfrom) {

	}
	else if (expInfo->ExceptionRecord->ExceptionAddress == m_instance->m_WSARecvFrom) {

	}
	else if (expInfo->ExceptionRecord->ExceptionAddress == m_instance->m_WSARecv) {

	}
	else {

	}

	return EXCEPTION_CONTINUE_SEARCH;
}

//rw=0:code
//rw=1:write
//rw=2:io
//rw=3:read write
//size:8,4,2,1
int HardBreakPoint(HANDLE ht, PVOID pAddress,int rw,int size)
{
	int ret = 0;
	CONTEXT context;
	
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	ret = GetThreadContext(ht, &context);

	int mask = 0;
	int num = 0;
	for (int i = 1; i <= 64; i = i * 4) {
		if ( (i & context.Dr7) == 0) {
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









int SetHardBreakPoint(LPVOID addr,int rw,int size) {
	int cnt = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(THREADENTRY32);
		if (Thread32First(hSnap, &te))
		{
			do
			{
				if (te.th32OwnerProcessID == GetCurrentProcessId())
				{
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
					if (hThread) {
						HardBreakPoint(hThread, addr,rw,size);
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





int SetHardBreakPoint(const char * dll,const char * fun) {
	int cnt = 0;
	HMODULE hm = GetModuleHandleA(dll);
	if (hm) {
		char* lpfunc = (char*)GetProcAddress(hm, fun);

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 te;
			te.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hSnap, &te))
			{
				do
				{
					if (te.th32OwnerProcessID == GetCurrentProcessId())
					{
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
						if (hThread) {
							HardBreakPoint(hThread, lpfunc,CODE_BREAKPOINT,1);
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





int __stdcall DebugThreadProc(int pid)
{
	BOOL nIsContinue = TRUE;
	DEBUG_EVENT debugEvent = { 0 };
	BOOL bRet = TRUE;
	DWORD dwContinue = DBG_CONTINUE;

	ElevationPrivilege();

	if (pid == -1) {
		pid = GetCurrentProcessId();
	}
	
	bRet = DebugActiveProcess(pid);
	if (!bRet)
	{
		log("DebugActiveProcess error: %d \n", GetLastError());
		return 0;
	}

	SetHardBreakPoint("kernel32.dll","CreateFileA");
	SetHardBreakPoint("ws2_32.dll", "recv");

	while (nIsContinue)
	{
		bRet = WaitForDebugEvent(&debugEvent, INFINITE);
		if (!bRet)
		{
			log("WaitForDebugEvent error: %d \n", GetLastError());
			return 0;
		}

		switch (debugEvent.dwDebugEventCode)
		{

		case EXCEPTION_DEBUG_EVENT:
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			//SetCreateFileHook(debugEvent.dwThreadId);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			break;

		case LOAD_DLL_DEBUG_EVENT:
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		}

		bRet = ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	}

	return 0;
}



int __stdcall TestThread() {
	int ret = 0;

	Network *network = new Network(IPPROTO_TCP, "127.0.0.1", 0x12345);
	HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network->TcpServer , (LPVOID)network, 0, 0);
	if (ht) {
		//WaitForSingleObject(ht, INFINITE);
		CloseHandle(ht);
	}

	network->TcpClient();

	return 0;
}


LONG WINAPI UnhandledExcepFilter(_EXCEPTION_POINTERS* ExceptionInfo) {
	return 0;
}

int __stdcall HardwareBP::BreakPointThead() {

	int ret = 0;

	SetUnhandledExceptionFilter(UnhandledExcepFilter);

	AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)HardwareBP::PvectoredExceptionHandler);

	//HardBreakPoint(&ret, DATA_RW_BREAKPOINT, 1);

	//HardBreakPoint(CreateFileA, CODE_BREAKPOINT, 1);

	//SetBreakPoint(CreateFileA);

	ret = -1;

	SetHardBreakPoint("kernel32.dll", "CreateFileA");
	//SetHardBreakPoint("ws2_32.dll", "WSARecv");
	//SetHardBreakPoint("ws2_32.dll", "WSARecvFrom");
	//SetHardBreakPoint("ws2_32.dll", "recv");
	//SetHardBreakPoint("ws2_32.dll", "recvfrom");

	while (1) {
		HANDLE hf = CreateFileA("mytest.dat", 0xc0000000, 0, 0, CREATE_ALWAYS, 0, 0);
		if (hf != INVALID_HANDLE_VALUE) {

			char* data = (char*)"hello\r\n";
			DWORD cnt = 0;
			int filesize = GetFileSize(hf, 0);
			ret = SetFilePointer(hf, filesize, 0, FILE_BEGIN);
			ret = WriteFile(hf, data, lstrlenA(data), &cnt, 0);

			CloseHandle(hf);
		}
		Sleep(3000);
	}

	return 0;
}





