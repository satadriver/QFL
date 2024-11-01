
#include <Windows.h>
#include "inject.h"
#include "utils.h"
#include "debug.h"
#include "main.h"

int fuzzEntry(int pid) {
	int ret = 0;
	ret = inject(pid,(char*) " ");

	return ret;
}



#ifdef _CONSOLE
int main(int argc, char** argv) {
	int ret = 0;

	//LPVOID addr = GetProcAddress(LoadLibraryA("ws2_32.dll"), "recv");
	//DWORD oldprotect = 0;
	//LPVOID address = GetAlignAddress(addr);
	//ret = VirtualProtectEx(GetCurrentProcess(), (LPVOID)address, 0X1000, PAGE_EXECUTE_READWRITE, &oldprotect);
	//*(int*)address = 0;

	//WinExec("D:\\vsProject\\QFL\\Debug\\target.exe",SW_SHOW);
	//Sleep(3000);
	//int pid = GetProcess("target.exe");
	//Debug* debug = new Debug("", pid,0);
	//ret = Debug::DebugThreadProc(debug);
	//return 0;

	if (argc <= 1) {
		return 0;
	}
	ret = 0;
	for (int i = 1; i < argc; ) {
		if (lstrcmpiA(argv[i], "--ih") == 0) {	//inject and hook
			char* strpid = argv[i + 1];
			ret = RemoteInject(atoi(strpid));
		}
		else if (lstrcmpiA(argv[i], "--dp") == 0) {
			char* strpid = argv[i + 1];
			int pid = atoi(strpid);
			Debug * debug = new Debug(0,(LPVOID)pid);
			ret = Debug::DebugThreadProc(debug);
		}
		else if (lstrcmpiA(argv[i], "--df") == 0) {
			char* fn = argv[i + 1];
			Debug* debug = new Debug( DEBUG_PROCESS,(LPVOID)fn);
			ret = Debug::DebugThreadProc(debug);
		}
		else if (lstrcmpiA(argv[i], "--f") == 0) {		//fuzz
			char* strpid = argv[i + 1];
			ret = fuzzEntry(atoi(strpid));
			i += 2;
		}
	}
	return 0;
}
#elif defined _WINDLL

#else
int __stdcall WinMain(HINSTANCE hinst, HINSTANCE prev, char* cmd, int show) {
	inject(GetProcess("notepad.exe"), (char*)"mytestfunc");
	return 0;

}

#endif

	
