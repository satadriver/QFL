#include <Windows.h>
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <windows.h>
#include <Tlhelp32.h>

#include "utils.h"
#include <iostream>
#include <Psapi.h>
#include "queue.h"
#include "log.h"

using namespace std;

extern "C" __declspec(dllexport) int mytestfunc() {
    MessageBoxA(0, "mytestfunc", "mytestfunc", MB_OK);
    return 0;
}

int ExecFunction(char* szfunc) {
    int ret = 0;
    HMODULE hm = GetModuleHandleA(0);
    ptrfunction lpfunc = (ptrfunction)GetProcAddress(hm, szfunc);
    if (lpfunc) {
        ret = lpfunc(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
    return ret;
}

int GetProcess(const char * pn)
{
    wchar_t wstrpn[1024];
    int pnlen = MultiByteToWideChar(CP_ACP, 0, pn, -1, wstrpn, sizeof(wstrpn) / sizeof(wchar_t));
    wstrpn[pnlen] = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return 0;
    }
    PROCESSENTRY32 pi;
    pi.dwSize = sizeof(PROCESSENTRY32); 
    BOOL bRet = Process32First(hSnapshot, &pi);
    while (bRet)
    {
        if ( _wcsicmp(pi.szExeFile , wstrpn) == 0) {
            return pi.th32ProcessID;
        }

        bRet = Process32Next(hSnapshot, &pi);
    }
    return 0;
}

string GetProcess(int pid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return string("");
    }
    PROCESSENTRY32 pi;
    pi.dwSize = sizeof(PROCESSENTRY32); 
    BOOL bRet = Process32First(hSnapshot, &pi);
    while (bRet)
    {
        if (pi.th32ProcessID == pid) {
            char pn[1024];
            int pnlen = WideCharToMultiByte(CP_ACP, 0, pi.szExeFile, -1, pn, sizeof(pn) / sizeof(char),0,0);
            pn[pnlen] = 0;
            return string(pn);
        }
        bRet = Process32Next(hSnapshot, &pi);
    }
    return string("");
}


BOOL PsKillProcess(const char* KillProcessName)
{
    int ret = 0;
    DWORD dwPid = GetProcess(KillProcessName);
    HANDLE hProcess = NULL;
    if (dwPid != 0)
    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
        if (hProcess != NULL)
        {
           ret = TerminateProcess(hProcess, 0);
        }
    }
    return ret;
}



int Is64Bit() {
    SYSTEM_INFO si = { 0 };

    int ret = 0;
    GetNativeSystemInfo(&si);
    if (si.dwPageSize == 0) {
        GetSystemInfo(&si);
    }
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        return TRUE;
    }
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        return 0;
    }

    return 0;
}


int IsProc64Bit(HANDLE h) {
    int wow64 = 0;
    int ret = IsWow64Process(h, &wow64);

    if (wow64) {
        return 32;
    }
    else {
        int bit64 = Is64Bit();   
        if (bit64) {
            return 64;
        }
        else {
            return 32;
        }
    }

    return 64;
}



string GetCurPath() {
    char szmod[MAX_PATH];
    int mlen = GetModuleFileNameA(0, szmod, sizeof(szmod));
    for (int i = mlen; i >= 0; i--) {
        if (szmod[i] == '\\') {
            szmod[i+1] = 0;
            return string(szmod);
        }
    }
    return "";
}


string RemovePath(string path) {

    for (int i = path.length(); i >= 0; i--) {
        if (path[i] == '\\') {

            return path.substr(i + 1);
        }
    }
    return "";
}



BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnable = TRUE)
{
    OutputDebugStringW(lpszPrivilege);
    BOOL bRet = FALSE;
    HANDLE hToken = NULL;
    HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, ::GetCurrentProcessId());
    if (!::OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        goto __EXIT;
    }
    LUID Luid;
    if (!::LookupPrivilegeValue(NULL, lpszPrivilege, &Luid))
    {
        goto __EXIT;
    }
    TOKEN_PRIVILEGES newPrivilege;
    newPrivilege.PrivilegeCount = 1;
    newPrivilege.Privileges[0].Luid = Luid;
    newPrivilege.Privileges[0].Attributes = //设置特权属性
        bEnable ?
        SE_PRIVILEGE_ENABLED :
        SE_PRIVILEGE_ENABLED_BY_DEFAULT;
    if (!::AdjustTokenPrivileges(hToken, FALSE, &newPrivilege,
        sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        CHAR s[64] = { 0 };
        wsprintfA(s, "AdjustTokenPrivileges error: %u\n", GetLastError());
        OutputDebugStringA(s);
        goto __EXIT;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        OutputDebugStringA("The token does not have the specified privilege. \n");
        goto __EXIT;
    }
    bRet = TRUE;
    OutputDebugStringA("Set OK");
__EXIT:
    if (hProcess)
    {
        ::CloseHandle(hProcess);
    }
    if (hToken)
    {
        ::CloseHandle(hToken);
    }
    return bRet;
}


VOID ElevationPrivilege()
{
    SetPrivilege(SE_CREATE_TOKEN_NAME);
    SetPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    SetPrivilege(SE_LOCK_MEMORY_NAME);
    SetPrivilege(SE_INCREASE_QUOTA_NAME);
    SetPrivilege(SE_UNSOLICITED_INPUT_NAME);
    SetPrivilege(SE_MACHINE_ACCOUNT_NAME);
    SetPrivilege(SE_TCB_NAME);
    SetPrivilege(SE_SECURITY_NAME);
    SetPrivilege(SE_TAKE_OWNERSHIP_NAME);
    SetPrivilege(SE_LOAD_DRIVER_NAME);
    SetPrivilege(SE_SYSTEM_PROFILE_NAME);
    SetPrivilege(SE_SYSTEMTIME_NAME);
    SetPrivilege(SE_PROF_SINGLE_PROCESS_NAME);
    SetPrivilege(SE_INC_BASE_PRIORITY_NAME);
    SetPrivilege(SE_CREATE_PAGEFILE_NAME);
    SetPrivilege(SE_CREATE_PERMANENT_NAME);
    SetPrivilege(SE_BACKUP_NAME);
    SetPrivilege(SE_RESTORE_NAME);
    SetPrivilege(SE_SHUTDOWN_NAME);
    SetPrivilege(SE_DEBUG_NAME);
    SetPrivilege(SE_AUDIT_NAME);
    SetPrivilege(SE_SYSTEM_ENVIRONMENT_NAME);
    SetPrivilege(SE_CHANGE_NOTIFY_NAME);
    SetPrivilege(SE_REMOTE_SHUTDOWN_NAME);
    SetPrivilege(SE_UNDOCK_NAME);
    SetPrivilege(SE_SYNC_AGENT_NAME);
    SetPrivilege(SE_ENABLE_DELEGATION_NAME);
    SetPrivilege(SE_MANAGE_VOLUME_NAME);
    SetPrivilege(SE_IMPERSONATE_NAME);
    SetPrivilege(SE_CREATE_GLOBAL_NAME);
    SetPrivilege(SE_TRUSTED_CREDMAN_ACCESS_NAME);
    SetPrivilege(SE_RELABEL_NAME);
    SetPrivilege(SE_INC_WORKING_SET_NAME);
    SetPrivilege(SE_TIME_ZONE_NAME);
    SetPrivilege(SE_CREATE_SYMBOLIC_LINK_NAME);
}


LPVOID GetProcessAddress(int pid,const char * dll,const char * fun) {
    HMODULE hm = GetProcModule(pid, dll);
    if (hm) {
        char* lpfunc = (char*)GetProcAddress(hm, fun);
        if (lpfunc) {
            return lpfunc;
        }
    }
    return 0;
}



int IsInSpace(int pid,char * moduleName,LPVOID buf) {
    HMODULE hm = GetProcModule(pid, moduleName);
    if (hm) {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hm;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((char*)hm + pDos->e_lfanew);
        ULONGLONG dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;

        if ((ULONGLONG)buf >= (ULONGLONG)hm && (ULONGLONG)buf < (ULONGLONG)hm + dwSizeOfImage) {
            return TRUE;
        }
    }
    return 0;
}


HMODULE GetProcModule(DWORD pid, CONST CHAR* moduleName) {	

    wchar_t wstrpn[1024];
    int pnlen = MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wstrpn, sizeof(wstrpn) / sizeof(wchar_t));
    wstrpn[pnlen] = 0;

    MODULEENTRY32 moduleEntry;
    HANDLE handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid); 
    if (!handle) {
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
            return moduleEntry.hModule; 
        }
    } while (Module32Next(handle, &moduleEntry));
    CloseHandle(handle);
    return 0;
}



LPVOID GetAlignAddress(LPVOID addr) {
    SYSTEM_INFO si = { 0 };

    GetNativeSystemInfo(&si);
    ULONGLONG ps = si.dwPageSize;

    ULONGLONG mask = ~(ps - 1);
    ULONGLONG ret = (ULONGLONG)addr & mask;
    return (LPVOID)ret;

}



int GetAddressBoundary(LPVOID addr, SIZE_T size,LPVOID*start,LPVOID*end) {
    int ret = 0;
    SYSTEM_INFO si = { 0 };
    GetNativeSystemInfo(&si);

    ULONGLONG ps = si.dwPageSize;

    ULONGLONG mask = ~(ps - 1);

    *start = (LPVOID)((ULONGLONG)addr & mask);

    *end = (LPVOID)(((ULONGLONG)addr + size + si.dwPageSize) & mask);

    return ret;
}


int ProcMemProtect(HANDLE hp,LPVOID addr, SIZE_T size,int v) {
    DWORD old = 0;
    return VirtualProtectEx(hp, addr, size, v, &old);

    int ret = 0;
    SYSTEM_INFO si = { 0 };

    GetNativeSystemInfo(&si);
    ULONGLONG ps = si.dwPageSize;

    ULONGLONG mask = ~(ps - 1);

    LPVOID start = (LPVOID)((ULONGLONG)addr & mask);

    //SIZE_T startsize = (ULONGLONG)addr - (ULONGLONG)start;

    LPVOID end = (LPVOID)( ((ULONGLONG)addr + size + si.dwPageSize) & mask) ;

    SIZE_T totalsize = (ULONGLONG)end - (ULONGLONG)start;
    
    ret = VirtualProtectEx(hp, start, totalsize, v, &old);
    return ret;
}



string GetNameFromPid(int pid) {

    char procName[MAX_PATH] ;

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (processHandle == NULL) {
        return "";
    }
    //auto len = GetModuleBaseNameA(processHandle, NULL, procName, MAX_PATH);
    //if (len == 0) {
    //    printf("Get base namefailed, err: %u", GetLastError());
    //}
    //printf("%s\n", tempProcName);

    GetModuleFileNameExA(processHandle, NULL, procName, MAX_PATH);
    //printf("%s\n", tempProcName);

    //GetProcessImageFileNameA(processHandle, procName, MAX_PATH);
    //printf("%s\n", tempProcName);

    CloseHandle(processHandle);
    
    return string(procName);
}


int IsFileOrPid(char* str) {
    int len = lstrlenA(str);
    if (len >= 4 && memcmp(str + len - 4, ".exe", 4) == 0) {
        return 0;
    }

    for (int i = 0; i < len; i++)
    {
        if (str[i] < '0' || str[i] > '9') {
            return 0;
        }
    }
    return 1;
}


int GetCallChain(HANDLE hp,LPVOID * rebp) {

    QueueClass q;
    int ret = 0;
    do  {
        LPVOID data[16] ;
        SIZE_T cnt = 0;
        ret = ReadProcessMemory(hp, rebp, data, sizeof(LPVOID)*16, &cnt);
        if (ret) {
            
            LPVOID* lpret = (LPVOID*)((ULONGLONG)data + sizeof(LPVOID));
            LPVOID retaddr = *lpret;

            q.Enqueue(retaddr);

            LPVOID* prev = (LPVOID*)(*data);
            rebp = prev;
        }
        else {
            break;
        }
    }while (1);

    int size = q.Size();
    if (size) {
        char buf[0x1000];
        int len = 0;
        for (int i = 0; i < size; i++) {
            LPVOID v = 0;
            q.Dequeue(&v);
            int section = sprintf_s(buf + len, sizeof(buf)," 0x%p ",v);
            len += section;
        }
        __log( "call stack:%s\r\n",buf);
    }

    return size;
}



LPVOID GetFuncStart(char* data) {
    
    for (int i = 0; i < 0x10000; i++) {
        if (memcmp((char*)data - i, "\x55\x8b\xec", 3) == 0) {
            if ( (ULONGLONG)(data - i) % 0x10 == 0) {
                if (*(data - i - 1) == 0xcc || *(data - i - 1) == 0xc3) {
                    return data - i;
                }
            }
        }
    } 
    return 0;
}