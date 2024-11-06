#pragma once


#include <windows.h>



#define DEFAULT_PE_BASE_ADDRESS		0x400000

class LoadPE {
public:
	static int __stdcall load(const char *szFileName);

	static char* getAddrFromName(char* module, const char* funname);

	static char* getAddrFromOrd(char* module, DWORD ord);

	static bool SetImageBase(char* chBaseAddress);

	static bool ImportTable(char* chBaseAddress);

	static bool RelocationTable(char* chBaseAddress,char * addr);

	static DWORD GetSizeOfImage(char* pFileBuff);

	static ULONGLONG GetImageBase(char* pFileBuff);

	static char * getEntry(char* pe);

	static bool MapFile(char* pFileBuff, char* chBaseAddress);

	static int RunPE(char* pFileBuff, DWORD dwSize);
};
