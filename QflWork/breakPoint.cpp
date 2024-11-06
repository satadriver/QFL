
#include "breakPoint.h"

#include "list.h"
#include <stdio.h>
#include "utils.h"
#include "debug.h"
#include "log.h"




BreakPoint::BreakPoint(int offset, int size) {

	m_bpList = new MyListClass();

	m_bpList->m_keyOffset = offset;
	m_bpList->m_keySize = size;

	m_addrList = new MyListClass();
}

BreakPoint::~BreakPoint() {
	delete m_bpList;
	delete m_addrList;
}


int BreakPoint::insertAddr(BufferNode* node) {
	int ret = 0;
	if (m_addrList == 0) {
		m_addrList = new MyListClass();
	}
	BufferNode* n = searchAddr((char*)node->buf,node->size);
	if (n == 0) {
		ret = m_addrList->InsertHead(&node->list);
	}
	return ret;
}


BufferNode* BreakPoint::bufHeader() {

	return (BufferNode *) m_addrList->m_list->next;
}

int BreakPoint::removeAddr(MyListEntry* list) {
	if (m_addrList == 0) {
		return FALSE;
	}
	return m_addrList->Remove(list);
}

BufferNode* BreakPoint::searchAddr(char* data, SIZE_T size) {
	if (m_addrList == 0) {
		return FALSE;
	}
	if (data == 0 || size == 0) {
		return 0;
	}

	BufferNode* n = (BufferNode *) m_addrList->m_list->next;
	BufferNode* b = n;

	do
	{
		if (n == 0) {
			break;
		}

		if ( (n->buf <= data) && (data + size <= (char*)n->buf + n->size) ) {
			return n;
		}
		else {
			if ( (n->bid.base <= data) && (data + size <= (char*)n->bid.top) )
			{
				return n;
			}
		}
		
		n = (BufferNode*)(n->list.next);

	} while (n != b);

	return 0;
}

MyListEntry* BreakPoint::header() {

	return m_bpList->m_list->next;
}

int BreakPoint::setKey(int offset, int size) {
	m_bpList->m_keyOffset = offset;
	m_bpList->m_keySize = size;
	return 0;
}

MyListEntry* BreakPoint::next(MyListEntry* list) {
	return list->next;
}

int BreakPoint::insert(MyListEntry* list) {
	int ret = 0;
	if (m_bpList == 0) {
		m_bpList = new MyListClass();
	}
	MyListEntry* node = search(m_bpList->m_keyOffset, (char*)list + m_bpList->m_keyOffset, m_bpList->m_keySize);
	if (node == 0) {
		ret = m_bpList->InsertHead(list);
	}
	return ret;
}

int BreakPoint::remove(MyListEntry* list) {
	if (m_bpList == 0) {
		return FALSE;
	}
	return m_bpList->Remove(list);
}


MyListEntry* BreakPoint::search(int offset, char* data, int size) {
	if (m_bpList == 0) {
		return FALSE;
	}
	return m_bpList->Search(offset, data, size);
}

int BreakPoint::SetProcBreakPoint(HANDLE hp,int pid,LPVOID addr, int cmd, LPVOID param) {
	int ret = 0;
	
	if (hp) {
		DWORD oldprotect = 0;
		LPVOID address = GetAlignAddress(addr);
		SYSTEM_INFO si = { 0 };
		GetNativeSystemInfo(&si);
		ret = VirtualProtectEx(hp, (LPVOID)address, si.dwPageSize, PAGE_EXECUTE_READWRITE, &oldprotect);

		unsigned char data[16] = { 0 };
		SIZE_T cnt = 0;
		ret = ReadProcessMemory(hp, addr, data, 16, &cnt);
		if (data[0] == 0xcc) {
			return 0;
		}

		BreakPointNode* node = new BreakPointNode();
		node->code = data[0];
		node->id.addr = addr;
		node->id.pid = pid;
		node->cmd = cmd;
		node->param = param;
		ret = insert(&(node->list));

		data[0] = 0xcc;
		ret = WriteProcessMemory(hp, addr, data, 1, &cnt);

		ret = ReadProcessMemory(hp, addr, data, 1, &cnt);
		if (data[0] != 0xcc) {
			__log("%s WriteProcessMemory %p:%x\r\n", __FUNCTION__, addr, data[0]);
		}
	}
	else {
		__log("%s process handle:%x\r\n", __FUNCTION__, hp);
	}
	return ret;
}


int BreakPoint::SetProcBreakPoint(int pid,LPVOID addr, int cmd, LPVOID param) {
	int ret = 0;

	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hp) {
		ret = SetProcBreakPoint(hp, pid,  addr, cmd, param);

		CloseHandle(hp);
	}

	return ret;
}


int BreakPoint::RestoreProcBreakPoint(HANDLE hp,int pid, int tid, LPVOID addr,int cmd,LPVOID param) {
	int ret = 0;
	HANDLE ht = OpenThread(THREAD_ALL_ACCESS, 0, tid);		//ReEntry function!
	if (ht) {
		int offset = offsetof(BreakPointNode, id);
		BPIdentifier id;
		id.addr = addr;
		id.pid = pid;
		BreakPointNode* node = (BreakPointNode*)search(offset, (char*)&id, sizeof(BPIdentifier));
		if (node == 0) {
			__log("Can not find break point address:%p, pid:%d\r\n", addr,pid);
			return 0;
		}

		DWORD oldprotect = 0;
		LPVOID address = GetAlignAddress(addr);
		SYSTEM_INFO si = { 0 };
		GetNativeSystemInfo(&si);
		ret = VirtualProtectEx(hp, (LPVOID)address, si.dwPageSize, PAGE_EXECUTE_READWRITE, &oldprotect);

		unsigned char data[16] = { 0 };
		SIZE_T cnt = 0;
		ret = ReadProcessMemory(hp, addr, data, 1, &cnt);
		if (data[0] != 0xcc) {
			__log("%s break point: %p loss int3 code:%x\r\n", __FUNCTION__, addr, data[0]);
			return 0;
		}
		
		ret = WriteProcessMemory(hp, addr, &node->code, 1, &cnt);

		ret = ReadProcessMemory(hp, addr, data, 1, &cnt);
		if (data[0] == 0xcc) {
			__log("%s WriteProcessMemory %p:%x\r\n", __FUNCTION__, addr, data[0]);
		}

		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		ret = GetThreadContext(ht, &context);
#ifdef _WIN64
		context.Rip--;
#else 
		context.Eip--;
#endif
		ret = SetThreadContext(ht, &context);
		CloseHandle(ht);

		if (cmd == HOOK_NETWORK_RETURN) {

			BufferNode* info = (BufferNode*)node->param;	
			if (info == 0) {
				__log("%s info:%u\r\n", __FUNCTION__, info);
			}
			else {
				if (node->cmd == HOOK_NETWORK_BUF) {
					ret = HOOK_NETWORK_BUF;
				}
				else if (node->cmd == HOOK_NETWORK_RETURN) {
					info->recvSize = (SIZE_T)param;
					ret = HOOK_NETWORK_RETURN;
				}
				SIZE_T size = (char*)info->bid.top - (char*)info->bid.base;
				//int res = ProcMemProtect(hp, (LPVOID)info->bid.base, size, PAGE_NOACCESS);
				//int res = ProcMemProtect(hp, info->buf, (SIZE_T)info->size, PAGE_NOACCESS);
			}
		}
		else {
			//
		}	
		
		remove(&(node->list));	
	}
	else {
		__log("%s error:%u\r\n", __FUNCTION__, GetLastError());
	}
	return ret;
}

int BreakPoint::RestoreProcBreakPoint(int pid,int tid,LPVOID addr,int cmd, LPVOID param) {
	int ret = 0;
	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hp) {
		ret = RestoreProcBreakPoint(hp,pid, tid, addr,cmd,param);
		CloseHandle(hp);
	}

	return ret;
}

int BreakPoint::SetBreakPoint(LPVOID addr) {
	int ret = 0;

	DWORD oldprotect = 0;
	//LPVOID address = GetAlignAddress(addr);
	ret = VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
	BreakPointNode* node = new BreakPointNode();
	node->code = *(char*)addr;
	node->id.addr = (unsigned char*)addr;
	node->id.pid = GetCurrentProcessId();
	node->tid = GetCurrentThreadId();

	insert(&(node->list));

	*(unsigned char*)addr =(unsigned char) 0xcc;

	return ret;
}


int BreakPoint::RestoreBreakPoint(int pid,int tid, LPVOID addr) {
	int ret = 0;
	HANDLE ht = OpenThread(THREAD_ALL_ACCESS, 0, tid);
	if (ht) {
		DWORD oldprotect = 0;
		//LPVOID address = GetAlignAddress(addr);
		ret = VirtualProtect((LPVOID)addr, 1, PAGE_EXECUTE_READWRITE, &oldprotect);

		int offset = offsetof(BreakPointNode, id);
		BPIdentifier id;
		id.addr = addr;
		id.pid = pid;
		BreakPointNode* node = (BreakPointNode*)search(offset, (char*)&id, sizeof(BPIdentifier));
		*(unsigned char*)addr = node->code;

		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
		ret = GetThreadContext(ht, &context);
#ifdef _WIN64
		context.Rip--;
#else 
		context.Eip--;
#endif
		ret = SetThreadContext(ht, &context);
		CloseHandle(ht);

		if (node->param) {

		}
		remove(&(node->list));
	}

	return ret;
}
