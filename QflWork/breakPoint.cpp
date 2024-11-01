
#include "breakPoint.h"

#include "list.h"


MyListClass g_mylist;



int SetBreakPoint(LPVOID addr) {
	int ret = 0;

	DWORD oldprotect = 0;
	ret = VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
	BreakPointNode* node = new BreakPointNode();
	node->code = *(char*)addr;
	node->addr = (unsigned char*)addr;

	g_mylist.InsertEnd(&(node->list));

	*(unsigned char*)addr =(unsigned char) 0xcc;

	return 0;
}


int RestoreBreakPoint(LPVOID addr) {
	int ret = 0;
	int offset = offsetof(BreakPointNode, addr);
	BreakPointNode* node = (BreakPointNode*)g_mylist.Search(offset, (char*)&addr, sizeof(addr));

	DWORD oldprotect = 0;
	ret = VirtualProtect((LPVOID)addr, 1,PAGE_EXECUTE_READWRITE, &oldprotect);

	*(unsigned char*)addr = node->code;

	g_mylist.Remove(&(node->list));

	return 0;
}
