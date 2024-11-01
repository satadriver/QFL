
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
	BufferNode* n = searchAddr((char*)&node->bid.base,sizeof(BufferIdentifier));
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

BufferNode* BreakPoint::searchAddr(char* data, int size) {
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
			return 0;
		}

		if (n->buf <= data && data < (char*)n->buf + n->size) {
			return n;
		}
		else if (n->bid.base <= data && data < (char*)n->bid.top ) {
			return n;
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
		ret = VirtualProtectEx(hp, (LPVOID)address, 0X1000, PAGE_EXECUTE_READWRITE, &oldprotect);

		unsigned char data[64] = { 0 };
		SIZE_T cnt = 0;
		ret = ReadProcessMemory(hp, addr, data, 16, &cnt);
		//__log("%s before %p:%x\r\n", __FUNCTION__, addr, data[0]);

		BreakPointNode* node = new BreakPointNode();
		node->code = *(char*)data;
		node->id.addr = (unsigned char*)addr;
		node->id.pid = pid;
		node->cmd = cmd;
		node->param = param;
		ret = insert(&(node->list));

		data[0] = 0xcc;
		ret = WriteProcessMemory(hp, addr, data, 1, &cnt);

		ret = ReadProcessMemory(hp, addr, data, 1, &cnt);

		//__log("%s after %p:%x\r\n", __FUNCTION__, addr, data[0]);
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

		int offset = offsetof(BreakPointNode, id);
		BPIdentifier id;
		id.addr = addr;
		id.pid = pid;
		BreakPointNode* node = (BreakPointNode*)search(offset, (char*)&id, sizeof(BPIdentifier));
		if (node == 0) {
			__log("search error\r\n");
			return 0;
		}

		DWORD oldprotect = 0;
		LPVOID address = GetAlignAddress(addr);
		ret = VirtualProtectEx(hp, (LPVOID)address, 0X1000, PAGE_EXECUTE_READWRITE, &oldprotect);

		unsigned char data[16] = { 0 };
		SIZE_T cnt = 0;
		ret = ReadProcessMemory(hp, addr, data, 1, &cnt);
		//__log("%s before %p:%x\r\n", __FUNCTION__, addr, data[0]);

		ret = WriteProcessMemory(hp, addr, &node->code, 1, &cnt);

		ret = ReadProcessMemory(hp, addr, data, 1, &cnt);
		//__log("%s aftre %p:%x\r\n", __FUNCTION__, addr, data[0]);

		if (node->cmd == HOOK_NETWORK_BUF || cmd == HOOK_NETWORK_RETURN) {

			BufferNode* info = (BufferNode*)node->param;
			
			if (node->cmd == HOOK_NETWORK_BUF) {
				
			}
			else if (cmd == HOOK_NETWORK_RETURN) {
				info->recvSize = (int)param;
			}
			ret = ProcMemProtect(hp, (LPVOID)info->buf, info->size, PAGE_NOACCESS);	
		}
		else {
			//
		}	

		if (node->param) {
			//delete node->param;
		}
		
		remove(&(node->list));
		//delete node;
		
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
	LPVOID address = GetAlignAddress(addr);
	ret = VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
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
		LPVOID address = GetAlignAddress(addr);
		ret = VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldprotect);
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

		int offset = offsetof(BreakPointNode, id);
		BPIdentifier id;
		id.addr = addr;
		id.pid = pid;
		BreakPointNode* node = (BreakPointNode*)search(offset, (char*)&id, sizeof(BPIdentifier));
		*(unsigned char*)addr = node->code;

		if (node->param) {
			//delete node->param;
		}
		remove(&(node->list));
		//delete node;
	}

	return ret;
}
