

#include <Windows.h>
#include <winsock.h>
#include <string>
#include <TlHelp32.h> 
#include "main.h"
#include <vector>
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#pragma comment(lib,"ws2_32.lib")

using namespace std;


HANDLE m_hMutex = 0;


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
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)//查看是否真的设置成功了
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



void AutoPowerOn()
{
    HKEY hKey;
    //std::string strRegPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    //1、找到系统的启动项  
    if (RegOpenKeyExA(HKEY_CURRENT_USER, ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0,
        KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) ///打开启动项       
    {
        //2、得到本程序自身的全路径
        CHAR strExeFullDir[MAX_PATH];
        GetModuleFileNameA(NULL, strExeFullDir, MAX_PATH);

        //3、判断注册表项是否已经存在
        CHAR strDir[MAX_PATH] = { 0 };
        DWORD nLength = MAX_PATH;
        long result = RegGetValueA(hKey, nullptr, ("GISRestart"), RRF_RT_REG_SZ, 0, strDir, &nLength);


        //4、已经存在
        if (result != ERROR_SUCCESS || lstrcmpiA(strExeFullDir, strDir) != 0)
        {
            //5、添加一个子Key,并设置值，"GISRestart"是应用程序名字（不加后缀.exe） 
            RegSetValueExA(hKey, ("GISRestart"), 0, REG_SZ, (LPBYTE)strExeFullDir,
                (lstrlenA(strExeFullDir) + 1) * sizeof(CHAR));

        }

        //6、关闭注册表
        RegCloseKey(hKey);
    }
}


//取消当前程序开机启动
void CanclePowerOn()
{
    HKEY hKey;
    //std::string strRegPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    //1、找到系统的启动项  
    if (RegOpenKeyExA(HKEY_CURRENT_USER, ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0,
        KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
    {
        //2、删除值
        RegDeleteValueA(hKey, ("GISRestart"));


        //3、关闭注册表
        RegCloseKey(hKey);
    }
}




int CheckExist() {
    m_hMutex = CreateMutexA(NULL, TRUE, "cltDrv_Mutext");
    if (m_hMutex && GetLastError() == ERROR_ALREADY_EXISTS)
    {

        CloseHandle(m_hMutex);
        m_hMutex = NULL;
        ExitProcess(0);
    }
    return TRUE;
}


int GetProcess(const char* pn)
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
    pi.dwSize = sizeof(PROCESSENTRY32); //第一次使用必须初始化成员
    BOOL bRet = Process32First(hSnapshot, &pi);
    while (bRet)
    {
        if (_wcsicmp(pi.szExeFile, wstrpn) == 0) {
            return pi.th32ProcessID;
        }
        //log("进程ID = %d ,进程路径 = %s\r\n", pi.th32ProcessID, pi.szExeFile);
        bRet = Process32Next(hSnapshot, &pi);
    }
    return 0;
}



