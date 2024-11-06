

#include <windows.h>


#include <stdio.h>






DWORD getAddrFromName(DWORD module, const char * funname) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);
	DWORD exptrva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	//DWORD size = nt->OptionalHeader.DataDirectory[0].Size;

	PIMAGE_EXPORT_DIRECTORY exptable = (PIMAGE_EXPORT_DIRECTORY)(exptrva + module);

	// const char * name = (const char*)(exp->Name + module);

	const char ** funnames = (const char **)(exptable->AddressOfNames + module);
	for (unsigned int i = 0; i < exptable->NumberOfNames; i++)
	{
		const char * functionname = (funnames[i] + module);
		if (lstrcmpiA((char*)funname, (char*)functionname) == 0)
		{
			WORD * ords = (WORD*)(exptable->AddressOfNameOrdinals + module);
			int idx = ords[i];
			DWORD * addrs = (DWORD *)(exptable->AddressOfFunctions + module);
			unsigned int addr = addrs[idx] + module;
			return addr;
		}
	}


	printf( "getAddrFromName module:%x,name:%s error\n", module,funname);

	return 0;
}

DWORD getAddrFromOrd(DWORD module, DWORD ord) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);
	DWORD rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;
	DWORD size = nt->OptionalHeader.DataDirectory[0].Size;

	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(rva + module);

	unsigned int funidx = ord - exp->Base;
	if (funidx < 0 || funidx >= exp->NumberOfFunctions)
	{

		printf( "getAddrFromOrd module:%x,ord:%d error\n", module, ord);

		return 0;
	}

	DWORD * addrs = (DWORD *)(exp->AddressOfFunctions + module);
	DWORD addr = addrs[funidx] + module;
	return addr;
}



bool relocTable(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)(chBaseAddress +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if ((char*)pLoc == (char*)pDos)
	{
		return TRUE;
	}

	DWORD dwDelta = (DWORD)chBaseAddress - pNt->OptionalHeader.ImageBase;

	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0)
	{
		WORD *pLocData = (WORD *)((char*)pLoc + sizeof(IMAGE_BASE_RELOCATION));

		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < nNumberOfReloc; i++)
		{
			if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000)
			{
				DWORD* pAddress = (DWORD *)((char*)pDos + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
				
				*pAddress += dwDelta;
			}
		}

		pLoc = (PIMAGE_BASE_RELOCATION)((char*)pLoc + pLoc->SizeOfBlock);
	}

	return TRUE;
}

bool mapFileWithAttrib(char* pFileBuff, char* chBaseAddress,DWORD * cr3)
{

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);

	DWORD dwSizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;
	memcpy(chBaseAddress, pFileBuff, dwSizeOfHeaders);

	//PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((char*)pNt + sizeof(IMAGE_NT_HEADERS));

	int nNumerOfSections = pNt->FileHeader.NumberOfSections;
	for (int i = 0; i < nNumerOfSections; i++, pSection++)
	{
		if ((0 == pSection->VirtualAddress) || (0 == pSection->SizeOfRawData))
		{
			continue;
		}

		char* chDestMem = (char*)((DWORD)chBaseAddress + pSection->VirtualAddress);
		char* chSrcMem = (char*)((DWORD)pFileBuff + pSection->PointerToRawData);
		DWORD dwSizeOfRawData = pSection->SizeOfRawData;
		memcpy(chDestMem, chSrcMem, dwSizeOfRawData);
	}

	return TRUE;
}

bool mapFile(char* pFileBuff, char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);

	DWORD dwSizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;
	memcpy(chBaseAddress, pFileBuff, dwSizeOfHeaders);

	//PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((char*)pNt + sizeof(IMAGE_NT_HEADERS));

	int nNumerOfSections = pNt->FileHeader.NumberOfSections;
	for (int i = 0; i < nNumerOfSections; i++, pSection++)
	{
		if ((0 == pSection->VirtualAddress) || (0 == pSection->SizeOfRawData))
		{
			continue;
		}

		char* chDestMem = (char*)((DWORD)chBaseAddress + pSection->VirtualAddress);
		char* chSrcMem = (char*)((DWORD)pFileBuff + pSection->PointerToRawData);
		DWORD dwSizeOfRawData = pSection->SizeOfRawData;
		memcpy(chDestMem, chSrcMem, dwSizeOfRawData);
	}

	return TRUE;
}


DWORD getSizeOfImage(char* pFileBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	DWORD dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;

	return dwSizeOfImage;
}


DWORD getEntry(char * pe) {
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pe;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pe + pDos->e_lfanew);
	DWORD entry = pNt->OptionalHeader.AddressOfEntryPoint;

	return entry;
}


DWORD getType(DWORD chBaseAddress) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(chBaseAddress + dos->e_lfanew);

	return nt->FileHeader.Characteristics;
}

DWORD getImageBase(char* pFileBuff)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	DWORD imagebase = pNt->OptionalHeader.ImageBase;

	return imagebase;
}

//why need to modify imagebase£¿
int setImageBase(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	pNt->OptionalHeader.ImageBase = (ULONG32)chBaseAddress;

	return TRUE;
}

DWORD importTable(DWORD module) {

	char szout[1024];

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);
	DWORD rva = nt->OptionalHeader.DataDirectory[1].VirtualAddress;
	DWORD size = nt->OptionalHeader.DataDirectory[1].Size;

	PIMAGE_IMPORT_DESCRIPTOR impd = (PIMAGE_IMPORT_DESCRIPTOR)(rva + module);
	
	while (1)
	{
		if (impd->FirstThunk == 0 && impd->ForwarderChain == 0 && impd->Name == 0 &&
			impd->OriginalFirstThunk == 0 && impd->TimeDateStamp == 0)
		{
			break;
		}

		const char * dllname = (const char *)(module + impd->Name);

		//__printf(szout, "find lib:%s\r\n", dllname);
		//__drawGraphChars((unsigned char*)szout, 0);

		//dllname here without path,so you need to set default path
		HMODULE dll = LoadLibraryA((LPSTR)dllname);
		if (NULL == dll)
		{
			impd++;
			continue;
		}

		PIMAGE_THUNK_DATA org = (PIMAGE_THUNK_DATA)(impd->OriginalFirstThunk + module);
		PIMAGE_THUNK_DATA first = (PIMAGE_THUNK_DATA)(impd->FirstThunk + module);
		while (1)
		{
			if (org->u1.Ordinal == 0 || first->u1.Ordinal == 0)
			{
				break;
			}

			DWORD addr = 0;
			if (org->u1.Ordinal & 0x80000000)
			{
				int ord = org->u1.Ordinal & 0xffff;
				addr = getAddrFromOrd((DWORD)dll, ord);
				if (addr <= 0)
				{
					printf( "getAddrFromOrd function no:%d from lib:%s error\r\n", ord, dllname);

					break;
				}
				else{
// 					__printf(szout, "getAddrFromOrd function no:%d address:%x from lib:%s ok\r\n", ord,addr, dllname);
// 					__drawGraphChars((unsigned char*)szout, 0);
				}
			}
			else {
				PIMAGE_IMPORT_BY_NAME impname = (PIMAGE_IMPORT_BY_NAME)(module + org->u1.AddressOfData);
				addr = getAddrFromName((DWORD)dll, (char*)impname->Name);
				if (addr <= 0)
				{
					printf( "getAddrFromOrd function:%s from lib:%s error\r\n", impname->Name, dllname);

					break;
				}
				else {
// 					__printf(szout, "getAddrFromOrd function:%s address:%x from lib:%s ok\r\n", impname->Name,addr, dllname);
// 					__drawGraphChars((unsigned char*)szout, 0);
				}
			}

			first->u1.Function = addr;

			org++;
			first++;
		}

		impd++;
	}
	return 0;
}





DWORD memLoadDll(char* filedata, char* addr) {
	mapFile(filedata, addr);
	importTable((DWORD)addr);
	relocTable(addr);
	setImageBase(addr);
	return (DWORD)addr;
}



			//mapFile((char*)data, (char*)dllptr);
			//setImageBase((char*)dllptr);
			//importTable((DWORD)dllptr);
			//relocTable((char*)dllptr);




DWORD rvaInFile(DWORD module, DWORD rva) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);
	int optsize = nt->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)module +
		dos->e_lfanew + sizeof(nt->Signature) + sizeof(IMAGE_FILE_HEADER) + optsize);

	int seccnt = nt->FileHeader.NumberOfSections;
	for (int i = 0; i < seccnt; i++)
	{
		DWORD end = sections[i].Misc.VirtualSize + sections[i].VirtualAddress;
		DWORD start = sections[i].VirtualAddress;
		if (rva >= start && rva <= end)
		{
			DWORD offset = rva - start;
			DWORD fileoffset = sections[i].PointerToRawData + offset;
			return fileoffset;
		}
	}

	return -1;
}


unsigned char * getRvaSectionName(DWORD module, DWORD rva) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)dos + dos->e_lfanew);
	int optsize = nt->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER sections = (PIMAGE_SECTION_HEADER)((DWORD)module +
		dos->e_lfanew + sizeof(nt->Signature) + sizeof(IMAGE_FILE_HEADER) + optsize);

	int seccnt = nt->FileHeader.NumberOfSections;
	for (int i = 0; i < seccnt; i++)
	{
		DWORD end = sections[i].Misc.VirtualSize + sections[i].VirtualAddress;
		DWORD start = sections[i].VirtualAddress;
		if (rva >= start && rva <= end)
		{
			return sections[i].Name;
		}
	}

	return 0;
}

