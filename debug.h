#pragma once

#include <Windows.h>
#include <iostream>
#include "breakPoint.h"
#include <unordered_map>
#include "queue.h"

using namespace std;

#define			NODE_TYPE_CODE			0
#define			NODE_TYPE_DATA			1
#define			NODE_TYPE_ADDR			2

#define			HOOK_NETWORK_FUN		0
#define			HOOK_NETWORK_RETURN		1
#define			HOOK_NETWORK_BUF		2
#define			HOOK_PROCESS_CREATE		3


#pragma pack(1)






#pragma pack()



class Debug {
public:
	
	Debug(int type, LPVOID param);
	~Debug();

	static int __stdcall DebugThreadProc(Debug* instance);

	int DebugProcess(DEBUG_EVENT* debug);

	int ProcessDataRange(HANDLE hp, int pid, LPVOID dataAddr, LPVOID codeAddr,int rw);

	int SetReceiveBP();

	static int __stdcall OutputBP(Debug* instance);

	int m_pid;

	int m_init;

	int m_type;

	string m_filename;

	LPVOID m_entryAddr;

	BreakPoint* m_breakPoint;

	//QueueClass m_qc;

	char* m_moduleBase;
	SIZE_T m_moduleSize;

	LPVOID m_recv;
	LPVOID m_recvfrom;
	LPVOID m_WSARecv;
	LPVOID m_WSARecvFrom;
};
