#pragma once



#include <Windows.h>
#include <winsock.h>
#include <string>
#include <TlHelp32.h> 
#include <vector>



using namespace std;




int GetProcess(const char* pn);

int CheckExist();

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnable);

VOID ElevationPrivilege();

void AutoPowerOn();
