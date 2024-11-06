
#include <Windows.h>
#include "hardwareBP.h"
#include "list.h"
#include "breakPoint.h"


int Procedure() {
    //MessageBoxA(0, "test_text", "test_cap", MB_OK);
    //HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HardwareBP::BreakPointThead, (LPVOID)0, 0, 0);
    //if (ht) {
    //    CloseHandle(ht);
    //}
    return 0;
}





#ifdef _WINDLL

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.

        Procedure();

        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:

        if (lpvReserved != nullptr)
        {
            break; // do not do cleanup if process termination scenario
        }

        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
#else

int __stdcall WinMain(HINSTANCE hinst, HINSTANCE prev, char* cmd, int show) {


    wchar_t * arg = GetCommandLine();
    int argc = 0;
    wchar_t ** argv = CommandLineToArgvW(arg, &argc);

    char strargv[1024];
    int slen = WideCharToMultiByte(CP_ACP, 0, argv[1], -1, strargv, sizeof(strargv), 0, 0);
    strargv[slen] = 0;
    HANDLE ht = 0;
    //HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DebugThreadProc, (LPVOID)0, 0, 0);
    //if (ht) 
    {
        //CloseHandle(ht);
    }

    /*
    ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)TestThread, (LPVOID)0, 0, 0);
    if (ht) {
        
        CloseHandle(ht);
    }

    ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HardwareBP::BreakPointThead, (LPVOID)0, 0, 0);
    if (ht) {
        //WaitForSingleObject(ht, INFINITE);
        CloseHandle(ht);
    }*/

    Sleep(-1);
    return 0;

}

#endif