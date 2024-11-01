

#include <Windows.h>
#include <iostream>
#include "test.h"



VOID SetHardBreakPoint(HANDLE hDebuggeeThread, PVOID pAddress)
{
    //1. ��ȡ�߳�������
    CONTEXT Context = { 0 };
    Context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hDebuggeeThread, &Context);
    //2. ���öϵ�λ��
    Context.Dr0 = (DWORD)pAddress;
    Context.Dr7 |= 1;
    //3. ���öϵ㳤�Ⱥ�����
    Context.Dr7 &= 0xfff0ffff;	//ִ�жϵ㣨16��17λ ��0�� 1�ֽڣ�18��19λ ��0��
    //5. �����߳�������
    SetThreadContext(hDebuggeeThread, &Context);
}


int __stdcall mythread() {
    int ret = 0;

    //LPVOID func = (LPVOID)GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateFileA");
    //SetHardBreakPoint(ht,func);

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
}

//LONG PvectoredExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo)
//{
 //   printf("hello\r\n");
 //   return EXCEPTION_CONTINUE_SEARCH;
//}


int __stdcall TestThread() {
    int ret = 0;

    HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)testServer, (LPVOID)0, 0, 0);
    if (ht) {
        //WaitForSingleObject(ht, INFINITE);
        CloseHandle(ht);
    }

    testClient("127.0.0.1", 0x12345);

    return 0;
}

int main()
{
    HANDLE ht = 0;
    //AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)PvectoredExceptionHandler);
    ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)TestThread, (LPVOID)0, 0, 0);
    if (ht) {

        CloseHandle(ht);
    }

    //ht= CreateThread(0, 0, (LPTHREAD_START_ROUTINE)mythread, 0, 0, 0);

    std::cout << "Hello World!\n";

    Sleep(-1);

    return 0;
}
