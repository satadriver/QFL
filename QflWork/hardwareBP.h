#pragma once

#include <Windows.h>

#define CODE_BREAKPOINT			0
#define DATA_W_BREAKPOINT		1
#define IO_BREAKPOINT			2
#define DATA_RW_BREAKPOINT		3

int __stdcall DebugThreadProc(int pid);

int __stdcall TestThread();

int HardBreakPoint(HANDLE ht, PVOID pAddress, int rw, int size);
int SetHardBreakPoint(LPVOID addr, int rw, int size);
int SetHardBreakPoint(const char* dll, const char* fun);

class HardwareBP {
public:

	HardwareBP();
	~HardwareBP();

	static HardwareBP* m_instance;

	LPVOID m_recv;
	LPVOID m_recvfrom;
	LPVOID m_WSARecv;
	LPVOID m_WSARecvFrom;

	static int __stdcall BreakPointThead();

	static LONG PvectoredExceptionHandler(_EXCEPTION_POINTERS* expInfo);
};