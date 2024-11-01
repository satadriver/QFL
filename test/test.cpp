




#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#define DEBUGGEE "D:\\vsProject\\QFL\\Debug\\target.exe"

//被调试进程ID,进程句柄，OEP
DWORD dwDebuggeePID = 0;

//被调试线程句柄
HANDLE hDebuggeeThread = NULL;
HANDLE hDebuggeeProcess = NULL;

//系统断点
BOOL bIsSystemInt3 = TRUE;

//被INT 3覆盖的数据
CHAR OriginalCode = 0;

//线程上下文
CONTEXT Context;

typedef HANDLE(__stdcall* FnOpenThread) (DWORD, BOOL, DWORD);

VOID InitDebuggeeInfo(DWORD dwPID, HANDLE hProcess)
{
	dwDebuggeePID = dwPID;
	hDebuggeeProcess = hProcess;
}

DWORD GetProcessId(LPTSTR lpProcessName)
{
	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == (HANDLE)-1)
	{
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcessSnap, &pe32))
	{
		do
		{
			if (!lstrcmp(lpProcessName, pe32.szExeFile))
				return (int)pe32.th32ProcessID;
		} while (Process32Next(hProcessSnap, &pe32));
	}
	else
	{
		CloseHandle(hProcessSnap);
	}

	return 0;
}

BOOL WaitForUserCommand()
{
	BOOL bRet = FALSE;
	CHAR command;

	printf("COMMAND>");
	return bRet;

	command = getchar();

	switch (command)
	{
	case 't':
		bRet = TRUE;
		break;
	case 'p':
		bRet = TRUE;
		break;
	case 'g':
		bRet = TRUE;
		break;
	}

	getchar();
	return bRet;
}

VOID SetHardBreakPoint(HANDLE hDebuggeeThread,PVOID pAddress)
{
	//1. 获取线程上下文
	Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hDebuggeeThread, &Context);
	//2. 设置断点位置
	Context.Dr0 = (DWORD)pAddress;
	Context.Dr7 |= 1;
	//3. 设置断点长度和类型
	Context.Dr7 &= 0xfff0ffff;	//执行断点（16、17位 置0） 1字节（18、19位 置0）
	//5. 设置线程上下文
	SetThreadContext(hDebuggeeThread, &Context);
}

BOOL Int3ExceptionProc(EXCEPTION_DEBUG_INFO* pExceptionInfo)
{
	BOOL bRet = FALSE;

	//1. 将INT 3修复为原来的数据（如果是系统断点，不用修复）
	if (bIsSystemInt3)
	{
		bIsSystemInt3 = FALSE;
		return TRUE;
	}
	else
	{
		WriteProcessMemory(hDebuggeeProcess, pExceptionInfo->ExceptionRecord.ExceptionAddress, &OriginalCode, 1, NULL);
	}

	//2. 显示断点位置
	printf("Int 3断点：0x%p \r\n", pExceptionInfo->ExceptionRecord.ExceptionAddress);

	//3. 获取线程上下文
	Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hDebuggeeThread, &Context);

#ifdef _WIN64
	//4. 修正EIP
#else
	Context.Eip--;
#endif
	SetThreadContext(hDebuggeeThread, &Context);

	//5. 显示反汇编代码、寄存器等

	/*
	硬件断点需要设置在被调试进程的的线程上下文中。
	因此当被调试程序触发调试器设置的INT 3断点时，此时设置硬件断点较为合理。
	*/
	SetHardBreakPoint(0,(PVOID)((DWORD)pExceptionInfo->ExceptionRecord.ExceptionAddress + 1));

	//6. 等待用户命令
	while (bRet == FALSE)
	{
		bRet = WaitForUserCommand();
		break;
	}

	return bRet;
}

BOOL AccessExceptionProc(EXCEPTION_DEBUG_INFO* pExceptionInfo)
{
	BOOL bRet = TRUE;

	return bRet;
}

BOOL SingleStepExceptionProc(EXCEPTION_DEBUG_INFO* pExceptionInfo)
{
	BOOL bRet = FALSE;

	//1. 获取线程上下文
	Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(hDebuggeeThread, &Context);
	//2. 判断是否是硬件断点导致的异常
	if (Context.Dr6 & 0xF)	//B0~B3不为空 硬件断点
	{
		//2.1 显示断点信息
		printf("硬件断点：%x 0x%x \n", Context.Dr7 & 0x00030000, Context.Dr0);
		//2.2 将断点去除
		Context.Dr0 = 0;
		Context.Dr7 &= 0xfffffffe;
	}
	else	//单步异常
	{
		//2.1 显示断点信息
		//printf("单步：0x%p \n", Context.Rip);
		//2.2 将断点去除
		Context.Dr7 &= 0xfffffeff;
	}

	SetThreadContext(hDebuggeeThread, &Context);

	//6. 等待用户命令
	while (bRet == FALSE)
	{
		bRet = WaitForUserCommand();
	}

	return bRet;
}

BOOL ExceptionHandler(DEBUG_EVENT* pDebugEvent)
{
	BOOL bRet = TRUE;
	EXCEPTION_DEBUG_INFO* pExceptionInfo = NULL;
	pExceptionInfo = &pDebugEvent->u.Exception;
	//得到线程句柄，后面要用
	FnOpenThread MyOpenThread = (FnOpenThread)GetProcAddress(LoadLibraryA("kernel32.dll"), "OpenThread");
	hDebuggeeThread = MyOpenThread(THREAD_ALL_ACCESS, FALSE, pDebugEvent->dwThreadId);

	switch (pExceptionInfo->ExceptionRecord.ExceptionCode)
	{
		//INT 3异常
	case EXCEPTION_BREAKPOINT:
		bRet = Int3ExceptionProc(pExceptionInfo);
		break;
		//访问异常
	case EXCEPTION_ACCESS_VIOLATION:
		bRet = AccessExceptionProc(pExceptionInfo);
		break;
		//单步执行
	case EXCEPTION_SINGLE_STEP:
		bRet = SingleStepExceptionProc(pExceptionInfo);
		break;
	}

	return bRet;
}

VOID SetInt3BreakPoint(LPVOID addr)
{
	unsigned char int3 = 0xCC;

	//1. 备份
	ReadProcessMemory(hDebuggeeProcess, addr, &OriginalCode, 1, NULL);
	//2. 修改
	WriteProcessMemory(hDebuggeeProcess, addr, &int3, 1, NULL);
}

//PVECTORED_EXCEPTION_HANDLER PvectoredExceptionHandler;

LONG PvectoredExceptionHandler( _EXCEPTION_POINTERS* ExceptionInfo)
{
	return EXCEPTION_CONTINUE_SEARCH;
}



HMODULE GetProcModule(DWORD pid, CONST CHAR* moduleName) {

	wchar_t wstrpn[1024];
	int pnlen = MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wstrpn, sizeof(wstrpn) / sizeof(wchar_t));
	wstrpn[pnlen] = 0;

	MODULEENTRY32 moduleEntry;
	HANDLE handle = NULL;
	handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!handle) {
		CloseHandle(handle);
		return NULL;
	}
	ZeroMemory(&moduleEntry, sizeof(MODULEENTRY32));
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(handle, &moduleEntry)) {
		CloseHandle(handle);
		return NULL;
	}

	do {
		if (_wcsicmp(moduleEntry.szModule, wstrpn) == 0)
		{
			CloseHandle(handle);
			return moduleEntry.hModule;
		}
	} while (Module32Next(handle, &moduleEntry));
	CloseHandle(handle);
	return 0;
}

int SetSocketBP(int pid) {
	HMODULE hm = GetProcModule(pid, "ws2_32.dll");
	if (hm) {
		char* lpfunc = (char*)GetProcAddress(hm, "recv");

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
							SetHardBreakPoint(hThread, (PVOID)lpfunc);
							CloseHandle(hThread);
						}

					}
				} while (Thread32Next(hSnap, &te));
			}
		}

		CloseHandle(hSnap);
	}

	return 0;
}


int SetCreateFileHook(int pid) {
	HMODULE hm = GetProcModule(pid, "kernel32.dll");
	if (hm) {
		char* lpfunc = (char*)GetProcAddress(hm, "CreateFileA");

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
		if (hSnap != INVALID_HANDLE_VALUE)
		{
			THREADENTRY32 te;
			te.dwSize = sizeof(THREADENTRY32);
			if (Thread32First(hSnap, &te))
			{
				do
				{
					//if (te.th32OwnerProcessID == pid)
					{
						HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
						if (hThread) {
							SetHardBreakPoint(hThread, (PVOID)lpfunc);
							CloseHandle(hThread);
						}

					}
				} while (Thread32Next(hSnap, &te));
			}
		}

		CloseHandle(hSnap);
	}

	return 0;
}

int main(int argc, char* argv[])
{
	BOOL nIsContinue = TRUE;
	DEBUG_EVENT debugEvent = { 0 };
	BOOL bRet = TRUE;
	DWORD dwContinue = DBG_CONTINUE;

	//1.创建调试进程
	STARTUPINFOA startupInfo = { 0 };
	PROCESS_INFORMATION pInfo = { 0 };
	GetStartupInfoA(&startupInfo);

	AddVectoredExceptionHandler(1,(PVECTORED_EXCEPTION_HANDLER )PvectoredExceptionHandler);

	bRet = CreateProcessA(DEBUGGEE, NULL, NULL, NULL, TRUE, DEBUG_PROCESS || DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &startupInfo, &pInfo);
	if (!bRet)
	{
		printf("CreateProcess error: %d \n", GetLastError());
		return 0;
	}

	hDebuggeeProcess = pInfo.hProcess;

	//2.调试循环
	while (nIsContinue)
	{
		bRet = WaitForDebugEvent(&debugEvent, INFINITE);
		if (!bRet)
		{
			printf("WaitForDebugEvent error: %d \n", GetLastError());
			return 0;
		}

		switch (debugEvent.dwDebugEventCode)
		{
			//1.异常
		case EXCEPTION_DEBUG_EVENT:
			bRet = ExceptionHandler(&debugEvent);
			if (!bRet)
				dwContinue = DBG_EXCEPTION_NOT_HANDLED;
			//SetHardBreakPoint((PCHAR)CreateFileA);
			//SetInt3BreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress+6);

			SetCreateFileHook(pInfo.dwProcessId);
			break;
			//2.
		case CREATE_THREAD_DEBUG_EVENT:
			break;
			//3.创建进程
		case CREATE_PROCESS_DEBUG_EVENT:
			//设置INT 3断点
			//SetHardBreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress);

			//SetInt3BreakPoint((PCHAR)debugEvent.u.CreateProcessInfo.lpStartAddress);
			break;
			//4.
		case EXIT_THREAD_DEBUG_EVENT:
			break;
			//5.
		case EXIT_PROCESS_DEBUG_EVENT:
			break;
			//6.
		case LOAD_DLL_DEBUG_EVENT:
			break;
			//7.
		case UNLOAD_DLL_DEBUG_EVENT:
			break;
			//8.
		case OUTPUT_DEBUG_STRING_EVENT:
			break;
		}

		bRet = ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
	}

	return 0;
}



