#include <windows.h>
#include <stdio.h>
#include "LoadPE.h"
#include "main.h"


VOID * ghThisHandle = 0;

PIMAGE_EXPORT_DIRECTORY pThisEAT = 0;


char * getAddrFromName(char* module, const char* funname) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);
	DWORD exptrva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//DWORD size = nt->OptionalHeader.DataDirectory[0].Size;

	PIMAGE_EXPORT_DIRECTORY exptable = (PIMAGE_EXPORT_DIRECTORY)(exptrva + module);

	// const char * name = (const char*)(exp->Name + module);

	const char** funnames = (const char**)(exptable->AddressOfNames + module);
	for (unsigned int i = 0; i < exptable->NumberOfNames; i++)
	{
		const char* functionname = (funnames[i] + (ULONGLONG)module);
		if (lstrcmpiA((char*)funname, (char*)functionname) == 0)
		{
			WORD* ords = (WORD*)(exptable->AddressOfNameOrdinals + module);
			int idx = ords[i];
			DWORD* addrs = (DWORD*)(exptable->AddressOfFunctions + module);
			ULONGLONG addr = (ULONGLONG)addrs[idx] + (ULONGLONG)module;
			return (char*) addr;
		}
	}


	printf("getAddrFromName module:%p,name:%s error\n", module, funname);

	return 0;
}

char * getAddrFromOrd(DWORD module, DWORD ord) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);
	DWORD rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
	DWORD size = nt->OptionalHeader.DataDirectory[0].Size;

	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(rva + module);

	unsigned int funidx = ord - exp->Base;
	if (funidx < 0 || funidx >= exp->NumberOfFunctions)
	{

		printf("getAddrFromOrd module:%x,ord:%d error\n", module, ord);

		return 0;
	}

	DWORD* addrs = (DWORD*)(exp->AddressOfFunctions + module);
	ULONGLONG addr = addrs[funidx] + module;
	return (char*)addr;
}

DWORD LoadPE::GetSizeOfImage(char* pFileBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	DWORD dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;

	return dwSizeOfImage;
}


ULONGLONG LoadPE::GetImageBase(char* pFileBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	ULONGLONG imagebase = pNt->OptionalHeader.ImageBase;

	return imagebase;
}

//why need to modify imagebase？
bool LoadPE::SetImageBase(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	pNt->OptionalHeader.ImageBase = (ULONGLONG)chBaseAddress;

	return TRUE;
}




int recoverEAT(char* dllbase) {
	int ret = 0;
	PIMAGE_DOS_HEADER thisdos = (PIMAGE_DOS_HEADER)ghThisHandle;
	PIMAGE_NT_HEADERS thisnt = (PIMAGE_NT_HEADERS)((char*)ghThisHandle + thisdos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY thiseat = (PIMAGE_EXPORT_DIRECTORY)((char*)ghThisHandle +
		thisnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	pThisEAT = thiseat;

	PIMAGE_DOS_HEADER dlldos = (PIMAGE_DOS_HEADER)dllbase;
	PIMAGE_NT_HEADERS dllnt = (PIMAGE_NT_HEADERS)(dllbase + dlldos->e_lfanew);

	int dlleatsize = dllnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PIMAGE_EXPORT_DIRECTORY dlleat = (PIMAGE_EXPORT_DIRECTORY)((char*)dllbase +
		dllnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD dwOldProtect = 0;
	ret = VirtualProtect(ghThisHandle, thisnt->OptionalHeader.SectionAlignment, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (FALSE == ret)
	{
		//Public::writelog("VirtualProtect error");
		return NULL;
	}

	int alignsizedlleat = thisnt->OptionalHeader.SectionAlignment - (dlleatsize % thisnt->OptionalHeader.SectionAlignment) + dlleatsize;

	ret = VirtualProtect(dlleat, alignsizedlleat, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	if (FALSE == ret)
	{
		//Public::writelog("VirtualProtect error");
		return NULL;
	}

	int rvadelta = dllbase - (char*)ghThisHandle;

	dlleat->Name = dlleat->Name + rvadelta;
	DWORD* dlladdresses = (DWORD*)(dllbase + dlleat->AddressOfFunctions);
	int totalfun = dlleat->NumberOfFunctions;
	for (int i = 0; i < totalfun; i++)
	{
		dlladdresses[i] = dlladdresses[i] + rvadelta;
	}
	dlleat->AddressOfFunctions = dlleat->AddressOfFunctions + rvadelta;

	DWORD* namefun = (DWORD*)(dllbase + dlleat->AddressOfNames);
	int funnames = dlleat->NumberOfNames;
	for (int i = 0; i < funnames; i++)
	{
		namefun[i] = namefun[i] + rvadelta;
	}

	dlleat->AddressOfNames = dlleat->AddressOfNames + rvadelta;

	dlleat->AddressOfNameOrdinals = dlleat->AddressOfNameOrdinals + rvadelta;

	thisnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (char*)dlleat -(char*) ghThisHandle;;
	thisnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size =
		dllnt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	return TRUE;
}






bool LoadPE::ImportTable(char* chBaseAddress)
{
	// 	char szGetModuleHandleA[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A',0 };
	// 	char szGetModuleHandleW[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','W',0 };
	// 	char szInitializeSListHead[] = { 'I','n','i','t','i','a','l','i','z','e','S','L','i','s','t','H','e','a','d',0 };

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pDos +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		char* lpDllName = (char*)((char*)pDos + pImportTable->Name);
		HMODULE hDll = (HMODULE)GetModuleHandleA((LPSTR)lpDllName);
		if (NULL == hDll)
		{
			hDll = LoadLibraryA(lpDllName);
			if (NULL == hDll)
			{
				pImportTable++;
				continue;
			}
		}

		DWORD i = 0;

		PIMAGE_THUNK_DATA lpImportNameArray = (PIMAGE_THUNK_DATA)((char*)pDos + pImportTable->OriginalFirstThunk);

		PIMAGE_THUNK_DATA lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((char*)pDos + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			FARPROC lpFuncAddress = NULL;

			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				lpFuncAddress = (FARPROC)GetProcAddress(hDll, (LPSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME lpImportByName = (PIMAGE_IMPORT_BY_NAME)((char*)pDos + lpImportNameArray[i].u1.AddressOfData);

				lpFuncAddress = (FARPROC)GetProcAddress(hDll, (LPSTR)lpImportByName->Name);
			}

			if (lpFuncAddress > 0)
			{
				lpImportFuncAddrArray[i].u1.Function = (ULONGLONG)lpFuncAddress;
			}

			i++;
		}

		pImportTable++;
	}

	return TRUE;
}

bool LoadPE::RelocationTable(char* chBaseAddress,char * addr)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)(chBaseAddress +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if ((char*)pLoc == (char*)pDos)
	{
		return TRUE;
	}

	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0)
	{
		WORD* pLocData = (WORD*)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));

		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		ULONGLONG dwDelta = (ULONGLONG)addr - pNt->OptionalHeader.ImageBase;

		for (int i = 0; i < nNumberOfReloc; i++)
		{
			if ((pLocData[i] & 0xF000) == 0x3000 || (pLocData[i] & 0xF000) == 0xA000)
				//if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000)
			{
				DWORD* pAddress = (DWORD*)((PBYTE)pDos + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));

				*pAddress +=(DWORD) dwDelta;
			}
		}

		pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
	}

	return TRUE;
}

bool LoadPE::MapFile(char* pFileBuff, char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);

	memcpy(chBaseAddress, pFileBuff, pNt->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	int nNumerOfSections = pNt->FileHeader.NumberOfSections;
	for (int i = 0; i < nNumerOfSections; i++, pSection++)
	{
		if ((0 == pSection->VirtualAddress) || (0 == pSection->SizeOfRawData))
		{
			continue;
		}

		char* chDestMem = (char*)(chBaseAddress + pSection->VirtualAddress);
		char* chSrcMem = (char*)(pFileBuff + pSection->PointerToRawData);

		memcpy(chDestMem, chSrcMem, pSection->SizeOfRawData);
	}

	return TRUE;
}




int LoadPE::RunPE(char* pFileBuff, DWORD dwSize)
{
	int ret = 0;

	DWORD dwSizeOfImage = GetSizeOfImage(pFileBuff);

	ULONGLONG imagebase = GetImageBase(pFileBuff);
	if (imagebase <= 0)
	{
		imagebase = DEFAULT_PE_BASE_ADDRESS;
	}

#ifdef _MYDEBUG
	wsprintfA(szout, "image base:%x,size:%x", imagebase, dwSizeOfImage);
	MessageBoxA(0, szout, szout, MB_OK);
#endif

	//使用MEM_RESERVE分配类型参数 Windows会以64 KB为边界计算该区域的起始地址 跟PE文件加载边界一致
	//使用MEM_COMMIT分配类型参数 区域的起始和结束地址都被计算到4KB边界
	//VirtualAlloc 当程序访问这部分内存时RAM内存才会被真正分配
	char* chBaseAddress = (char*)VirtualAlloc((char*)imagebase, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NULL == chBaseAddress)
	{
#ifdef _MYDEBUG
		wsprintfA(szout, "VirtualAlloc address:%x error", imagebase);
		MessageBoxA(0, szout, szout, MB_OK);
#endif
		chBaseAddress = (char*)VirtualAlloc(0, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (NULL == chBaseAddress)
		{
#ifdef _MYDEBUG
			wsprintfA(szout, "VirtualAlloc address:%x error", imagebase);
			MessageBoxA(0, szout, szout, MB_OK);
#endif
			return NULL;
		}
	}

	RtlZeroMemory(chBaseAddress, dwSizeOfImage);

	ret = MapFile(pFileBuff, chBaseAddress);

	//Reloc::recovery((DWORD)chBaseAddress);
	ret = RelocationTable(chBaseAddress,0);

	//ImportFunTable::recover((DWORD)chBaseAddress);
	ret = ImportTable(chBaseAddress);

	DWORD dwOldProtect = 0;
	if (FALSE == VirtualProtect(chBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		VirtualFree(chBaseAddress, dwSizeOfImage, MEM_DECOMMIT|MEM_RELEASE);
		VirtualFree(chBaseAddress, 0, MEM_RELEASE);
#ifdef _MYDEBUG
		wsprintfA(szout, "VirtualProtect address:%x error", imagebase);
		MessageBoxA(0, szout, szout, MB_OK);
#endif
		return NULL;
	}

	ret = SetImageBase(chBaseAddress);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(chBaseAddress + dos->e_lfanew);


	return TRUE;
}

