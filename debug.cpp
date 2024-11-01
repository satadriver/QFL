
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#include <tlhelp32.h>
#include "log.h"
#include "utils.h"

#include "debug.h"
#include "breakPoint.h"
#include "hwBreakPoint.h"

#include <unordered_map>

#ifdef _WIN64
#include "hde/hde64.h"
#else
#include "hde/hde32.h"
#endif


#define OUTPUT_INTERVAL 10

Debug::~Debug() {

}



Debug::Debug(int type,LPVOID param) {
	m_type = type;
	if (type == DEBUG_PROCESS) {
		m_filename = (char*)param;
	}
	else {
		m_pid = (int) param;
	}
	
	m_init = 0;
	
	int offset = offsetof(BreakPointNode, id);
	m_breakPoint = new BreakPoint(offset,sizeof(BPIdentifier));

	HANDLE ht = CreateThread(0, 0,(LPTHREAD_START_ROUTINE)OutputBP, this, 0, 0);
	if (ht) {
		CloseHandle(ht);
	}
}


int __stdcall Debug::OutputBP(Debug* instance) {

	while (1) {

		Sleep(1000* OUTPUT_INTERVAL);

		BufferNode* node = (BufferNode*)instance->m_breakPoint->bufHeader();
		BufferNode* base = node;
		do
		{
			if (node) {

				if (node->count )
				{

					ULONG64 offset = ((ULONG64)node->bpData - (ULONG64)node->buf);
					__log("pid:%d,tid:%d,code:%p,data:%p,buffer:%p,size:%x,base:%p,top:%p,offset:%I64d,"\
						"rw:%d,socket:%d,recvsize:%d,start:%I64d,end:%I64d,count:%I64d\r\n",
						node->pid, node->tid,node->bpCode, node->bpData,node->buf, node->size, 
						node->bid.base,node->bid.top,
						offset, node->rw, node->sock, node->recvSize, 
						node->startTime, node->endTime, node->count);
				}
				node = (BufferNode*)node->list.next;
			}
			else {
				break;
			}
		} while (node != base);
	}
	
	return 0;
}


int Debug::ProcessDataRange(HANDLE hp, int pid, LPVOID dataAddr, LPVOID codeAddr,int rw) {
	INT ret = 0;

	BufferNode* node = (BufferNode*)m_breakPoint->bufHeader();
	BufferNode* base = node;
	do
	{
		if (node) {

			if (pid == node->pid  && node->bid.base <= dataAddr && node->bid.top > dataAddr) {

				ret = ProcMemProtect(hp, node->buf, (SIZE_T)node->size,PAGE_EXECUTE_READWRITE);
			
				if ((node->buf <= dataAddr) && ((char*)node->buf + node->size > dataAddr)) {
					if (node->startTime == 0) {
						node->startTime = GetTickCount64();
					}
					node->endTime = GetTickCount64();
					node->count++;
					node->rw = rw;
					node->bpCode = codeAddr;
					node->bpData = dataAddr;
					
					unsigned char instructs[64] = { 0 };
					ret = ReadProcessMemory(hp, codeAddr, instructs, 16, 0);
#ifdef _WIN64
					hde64s asm64 = { 0 };
					int instrLen = hde64_disasm(instructs, &asm64);
#else
					hde32s asm32 = { 0 };
					int instrLen = hde32_disasm(instructs, &asm32);
#endif
					ret = m_breakPoint->SetProcBreakPoint(hp, pid, (char*)codeAddr + instrLen, HOOK_NETWORK_BUF, node);
					ret = ProcMemProtect(hp, node->buf, (SIZE_T)node->size,PAGE_EXECUTE_READWRITE);
				}
				else  {
					unsigned char instructs[64] = { 0 };
#ifdef _WIN64
					hde64s asm64 = { 0 };
					int instrLen = hde64_disasm(instructs, &asm64);
#else
					hde32s asm32 = { 0 };
					int instrLen = hde32_disasm(instructs, &asm32);
#endif
					ret = ReadProcessMemory(hp, codeAddr, instructs, 16, 0);
					ret = m_breakPoint->SetProcBreakPoint(hp, pid, (char*)codeAddr + instrLen, HOOK_NETWORK_BUF, node);
					ret = ProcMemProtect(hp, node->buf, (SIZE_T)node->size, PAGE_EXECUTE_READWRITE);
				}
			}
			else {
				//error
			}

			node = (BufferNode*)node->list.next;
		}
		else {
			break;
		}
	} while (node != base);

	return ret;
}



int Debug::DebugProcess(DEBUG_EVENT * debug) {
	int ret = 0;

	//unknown software exception(0x80000004)

	DWORD code = debug->u.Exception.ExceptionRecord.ExceptionCode;

	int times = debug->u.Exception.dwFirstChance;
	if (times > 1) {
		__log("times:%d\r\n", times);
	}

	unsigned char* addr = (unsigned char*)debug->u.Exception.ExceptionRecord.ExceptionAddress;
	if (addr == 0) {
		__log("addr 0\r\n");
		return 0;
	}

	//OpenProcess and OpenThread can reentry,that means the one same handle can be opened/closed for many times in same time
	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, debug->dwProcessId);
	HANDLE ht = OpenThread(THREAD_ALL_ACCESS, 0, debug->dwThreadId);

	if (hp && ht && addr) {

		if ( code == EXCEPTION_ACCESS_VIOLATION) {
			int paramCnt = debug->u.Exception.ExceptionRecord.NumberParameters;

			int rw = debug->u.Exception.ExceptionRecord.ExceptionInformation[0];
			LPVOID dataAddr = (LPVOID)debug->u.Exception.ExceptionRecord.ExceptionInformation[1];

			ret = ProcessDataRange(hp, debug->dwProcessId, dataAddr, addr,rw);
			if (ret) {

			}
		}
		else if (code == EXCEPTION_SINGLE_STEP) {
			__log("EXCEPTION_SINGLE_STEP\r\n");
		}
		else if (code == STATUS_ILLEGAL_INSTRUCTION) {
			__log("STATUS_ILLEGAL_INSTRUCTION\r\n");
		}
		else if( code == EXCEPTION_BREAKPOINT ) {
			CONTEXT context;
			context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
			ret = GetThreadContext(ht, &context);

			unsigned char data[16] = { 0 };
			ret = ReadProcessMemory(hp, addr, data, 1, 0);
			if (data[0] == 0xcc) {

				if (addr == m_recv || addr == m_recvfrom) {

					ret = m_breakPoint->RestoreProcBreakPoint(hp, debug->dwProcessId,
						debug->dwThreadId, addr, HOOK_NETWORK_FUN,0);

					LPVOID v[8] = { 0 };
#ifdef _WIN64
					ret = ReadProcessMemory(hp, (LPVOID)context.Rsp, v, sizeof(v), 0);
#else
					ret = ReadProcessMemory(hp, (LPVOID)context.Esp, v, sizeof(v), 0);
#endif
					//ret = ProcMemProtect(hp, v[2], (SIZE_T)v[3]&0xffffffff, PAGE_NOACCESS);
					//HardBreakPoint(ht, v[0], DATA_RW_BREAKPOINT, 1);		

					BufferNode* bn = new BufferNode;
					memset(bn, 0, sizeof(BufferNode));
					bn->buf = v[2];
					bn->size = (SIZE_T)v[3];
					bn->sock = (int)v[1];
					bn->pid = debug->dwProcessId;
					bn->tid = debug->dwThreadId;
					
					GetAddressBoundary(bn->buf, bn->size, &bn->bid.base, &bn->bid.top);

					m_breakPoint->insertAddr(bn);
					
					m_breakPoint->SetProcBreakPoint(debug->dwProcessId, v[0], HOOK_NETWORK_RETURN, bn);
				}
				else if (addr == m_WSARecv || addr == m_WSARecvFrom) {
					/*
					  int WSAAPI WSARecv(
					  [in]      SOCKET                             s,
					  [in, out] LPWSABUF                           lpBuffers,
					  [in]      DWORD                              dwBufferCount,
					  [out]     LPDWORD                            lpNumberOfBytesRecvd,
					  [in, out] LPDWORD                            lpFlags,
					  [in]      LPWSAOVERLAPPED                    lpOverlapped,
					  [in]      LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
					);

					int WSAAPI WSARecvFrom(
					  [in]      SOCKET                             s,
					  [in, out] LPWSABUF                           lpBuffers,
					  [in]      DWORD                              dwBufferCount,
					  [out]     LPDWORD                            lpNumberOfBytesRecvd,
					  [in, out] LPDWORD                            lpFlags,
					  [out]     sockaddr                           *lpFrom,
					  [in, out] LPINT                              lpFromlen,
					  [in]      LPWSAOVERLAPPED                    lpOverlapped,
					  [in]      LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
					);
					*/
					ret = m_breakPoint->RestoreProcBreakPoint(hp, debug->dwProcessId,
						debug->dwThreadId, addr, HOOK_NETWORK_FUN,0);

					LPVOID v[8] = { 0 };
#ifdef _WIN64
					ret = ReadProcessMemory(hp, (LPVOID)context.Rsp, v, sizeof(v), 0);
#else
					ret = ReadProcessMemory(hp, (LPVOID)context.Esp, v, sizeof(v), 0);
#endif
					BufferNode* bn = new BufferNode;
					memset(bn, 0, sizeof(BufferNode));

					LPWSABUF wsabufs = (LPWSABUF)v[2];
					int wsabufCnt = (int) v[3];
					WSABUF wbuf;
					ret = ReadProcessMemory(hp, (LPVOID)wsabufs, &wbuf, sizeof(WSABUF), 0);

					bn->buf = wbuf.buf;
					bn->size = (SIZE_T)wbuf.len;

					bn->sock = (int)v[1];
					bn->pid = debug->dwProcessId;
					bn->tid = debug->dwThreadId;

					//sockaddr_in sa;
					//ret = ReadProcessMemory(hp, (LPVOID)v[6], &sa, sizeof(sockaddr_in), 0);

					GetAddressBoundary(bn->buf, bn->size, &bn->bid.base, &bn->bid.top);

					m_breakPoint->insertAddr(bn);

					m_breakPoint->SetProcBreakPoint(debug->dwProcessId, v[0], HOOK_NETWORK_RETURN, bn);
				}
				else {
					if (addr == m_entryAddr) {
						
						ret = m_breakPoint->RestoreProcBreakPoint(hp, debug->dwProcessId,
							debug->dwThreadId, addr, HOOK_PROCESS_CREATE, (LPVOID)0);
						SetReceiveBP();
					}
					else {
#ifdef _WIN64
						int recvLen = (int)context.Rax & 0xffffffff;
#else
						int recvLen = context.Eax;
#endif
						ret = m_breakPoint->RestoreProcBreakPoint(hp, debug->dwProcessId,
							debug->dwThreadId, addr, HOOK_NETWORK_RETURN, (LPVOID)recvLen);
						SetReceiveBP();
					}
				}
			}
			else
			{
				if (context.Dr6 & 0x8000) {
					//
				}
				else if (context.Dr6 & 0x4000) {
					//
				}
				else if (context.Dr6 & 0x2000) {
					//
				}
				else if (context.Dr6 & 0x0f) {
					LPVOID hardAddr = 0;
					if (context.Dr6 & 0x01) {
						hardAddr = (LPVOID)context.Dr0;
						context.Dr7 &= 0xfffffffe;
						context.Dr6 &= 0xfffffffe;
						ret = SetThreadContext(ht, &context);
					}
					else if (context.Dr6 & 0x02) {
						context.Dr7 &= 0xfffffffd;
						context.Dr6 &= 0xfffffffd;
						hardAddr = (LPVOID)context.Dr1;
						ret = SetThreadContext(ht, &context);
					}
					else if (context.Dr6 & 0x04) {
						context.Dr7 &= 0xfffffffb;
						context.Dr6 &= 0xfffffffb;
						hardAddr = (LPVOID)context.Dr2;
						ret = SetThreadContext(ht, &context);
					}
					else if (context.Dr6 & 0x08) {
						context.Dr7 &= 0xfffffff7;
						context.Dr6 &= 0xfffffff7;
						hardAddr = (LPVOID)context.Dr3;
						ret = SetThreadContext(ht, &context);
					}

					if (hardAddr == m_recv) {

						LPVOID v[8] = { 0 };
#ifdef _WIN64
						ret = ReadProcessMemory(hp, (LPVOID)context.Rsp, v, sizeof(v), 0);
#else
						ret = ReadProcessMemory(hp, (LPVOID)context.Esp, v, sizeof(v), 0);
#endif
						HardBreakPoint(ht, v[2], DATA_RW_BREAKPOINT, 1);
					}
					else if (hardAddr == m_WSARecv) {

					}
					else if (hardAddr == m_WSARecvFrom) {

					}
					else if (hardAddr == m_recvfrom) {
						LPVOID v[8] = { 0 };
#ifdef _WIN64
						ret = ReadProcessMemory(hp, (LPVOID)context.Rsp, v, sizeof(v), 0);
#else
						ret = ReadProcessMemory(hp, (LPVOID)context.Esp, v, sizeof(v), 0);
#endif
						HardBreakPoint(ht, v[2], DATA_RW_BREAKPOINT, 1);
					}
					else if(hardAddr){
						ret = ReadProcessMemory(hp, (LPVOID)hardAddr, data, sizeof(LPVOID), 0);
					}
				}
			}
		}
		CloseHandle(ht);
		CloseHandle(hp);
	}
	return 0;
}



#ifndef _WIN64
void EnableSingleStep(){
	__asm {
		pushfd
		or [esp],0x100
		popfd
	}
}
#endif


int __stdcall Debug::DebugThreadProc(Debug * instance)
{
	BOOL nIsContinue = TRUE;
	DEBUG_EVENT debugEvent = { 0 };
	BOOL bRet = TRUE;
	DWORD dwContinue = DBG_CONTINUE;

	ElevationPrivilege();

#ifndef _WIN64
	EnableSingleStep();
#endif

	if (instance->m_type == DEBUG_PROCESS) {

		STARTUPINFOA startupInfo = { 0 };
		PROCESS_INFORMATION pInfo = { 0 };
		GetStartupInfoA(&startupInfo);
		bRet = CreateProcessA(instance->m_filename.c_str(), NULL, NULL, NULL, 
			TRUE, DEBUG_PROCESS || DEBUG_ONLY_THIS_PROCESS,NULL, NULL, &startupInfo, &pInfo);
		if (pInfo.hProcess) {
			CloseHandle(pInfo.hProcess);
			
		}
		if (pInfo.hThread) {
			CloseHandle(pInfo.hThread);
		}
		if (!bRet)
		{
			__log("%s %s CreateProcessA error: %d \r\n", __FILE__, __FUNCTION__, GetLastError());
			return 0;
		}
		instance->m_pid = pInfo.dwProcessId;
	}
	else {
		if (instance->m_pid == 0) {
			instance->m_pid = GetCurrentProcessId();
		}
		bRet = DebugActiveProcess(instance->m_pid);
		if (!bRet)
		{
			__log("%s %s DebugActiveProcess error: %d \r\n", __FILE__, __FUNCTION__, GetLastError());
			return 0;
		}
		instance->m_filename = GetNameFromPid(instance->m_pid);

		instance->SetReceiveBP();
	}

	while (nIsContinue)
	{
		DWORD code = debugEvent.u.Exception.ExceptionRecord.ExceptionCode;
		bRet = WaitForDebugEvent(&debugEvent, INFINITE);
		if (!bRet)
		{
			__log("%s %s WaitForDebugEvent error: %d \r\n", __FILE__, __FUNCTION__, GetLastError());
			return 0;
		}

		switch (debugEvent.dwDebugEventCode)
		{
			case EXCEPTION_DEBUG_EVENT:
			{
				//LPVOID addr = GetProcessAddress(instance->m_pid, "kernel32.dll", "CreateFileA");
				//SetProcBreakPoint(pid, addr);
				//SetHardBreakPoint(instance->m_pid, "kernel32.dll", "CreateFileA");
				if (instance->m_init == 0) 
				{
					//instance->DebugProcess(&debugEvent);
					instance->m_init = 1;
				}
				else {
					instance->DebugProcess(&debugEvent);
				}		
				break;
			}

			case CREATE_THREAD_DEBUG_EVENT:
			{
				break;
			}

			case CREATE_PROCESS_DEBUG_EVENT:
			{
				LPVOID entry = (LPVOID)debugEvent.u.CreateProcessInfo.lpStartAddress;
				instance->m_entryAddr = entry;
				instance->m_breakPoint->SetProcBreakPoint(instance->m_pid, entry, HOOK_PROCESS_CREATE,0);
				break;
			}

			case EXIT_THREAD_DEBUG_EVENT: 
			{
				break;
			}

			case EXIT_PROCESS_DEBUG_EVENT: 
			{
				ExitProcess(0);
				break;
			}

			case LOAD_DLL_DEBUG_EVENT: 
			{
				char* fn =(char*) debugEvent.u.LoadDll.lpImageName;
				//if (lstrcmpiA(fn, "ws2_32.dll") == 0) 
				{

				}

				break;
			}

			case UNLOAD_DLL_DEBUG_EVENT: 
			{
				break;
			}

			case OUTPUT_DEBUG_STRING_EVENT: 
			{
				break;
			}
		}

		bRet = ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	}

	return 0;
}



int Debug::SetReceiveBP() {
	if (m_recv == 0) {
		m_recv = (LPVOID)GetProcessAddress(m_pid, "ws2_32.dll", "recv");
		m_recvfrom = (LPVOID)GetProcessAddress(m_pid, "ws2_32.dll", "recvfrom");
		m_WSARecv = (LPVOID)GetProcessAddress(m_pid, "ws2_32.dll", "WSARecv");
		m_WSARecvFrom = (LPVOID)GetProcessAddress(m_pid, "ws2_32.dll", "WSARecvFrom");
	}

	m_breakPoint->SetProcBreakPoint(m_pid, m_recv, HOOK_NETWORK_FUN, 0);
	m_breakPoint->SetProcBreakPoint(m_pid, m_recvfrom, HOOK_NETWORK_FUN, 0);
	m_breakPoint->SetProcBreakPoint(m_pid, m_WSARecv, HOOK_NETWORK_FUN, 0);
	m_breakPoint->SetProcBreakPoint(m_pid, m_WSARecvFrom, HOOK_NETWORK_FUN, 0);

	//SetHardBreakPoint(instance->m_pid, "ws2_32.dll", "recv");
	//SetHardBreakPoint(instance->m_pid, "ws2_32.dll", "recvfrom");
	//SetHardBreakPoint(instance->m_pid, "ws2_32.dll", "WSARecv");
	//SetHardBreakPoint(instance->m_pid, "ws2_32.dll", "WSARecvFrom");
	return 0;
}