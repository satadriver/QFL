#pragma once

#include <Windows.h>
#include "list.h"

#pragma pack(1)

typedef struct {
	LPVOID addr;
	int pid;
}BPIdentifier;

typedef struct {
	MyListEntry  list;
	BPIdentifier id;
	unsigned char code;
	int tid;
	int cmd;
	LPVOID param;
}BreakPointNode;

typedef struct {
	LPVOID base;
	LPVOID top;
}BufferIdentifier;

typedef struct {
	MyListEntry  list;
	BufferIdentifier bid;
	LPVOID buf;
	SIZE_T size;

	int pid;
	int tid;

	int sock;
	sockaddr_in node;
	SIZE_T recvSize;

	int rw;
	__int64 startTime;
	__int64 endTime;
	__int64 count;

	LPVOID bpData;
	LPVOID bpCode;

}BufferNode;

#pragma pack()

class BreakPoint {
public:
	BreakPoint(int offset, int size);
	~BreakPoint();

	MyListEntry* header();

	int setKey(int offset, int size);

	MyListEntry* next(MyListEntry* list);

	int insert(MyListEntry* list);

	int remove(MyListEntry* list);

	MyListEntry* search(int offset, char* data, int size);

	MyListClass* m_bpList ;

	MyListClass* m_addrList;

	BufferNode* bufHeader();

	int insertAddr(BufferNode* list);

	int removeAddr(MyListEntry* list);

	BufferNode* searchAddr(char* data, SIZE_T size);


	int SetProcBreakPoint(HANDLE hp, int pid, LPVOID addr, int cmd, LPVOID param);

	int SetProcBreakPoint(int pid, LPVOID addr, int cmd, LPVOID param);


	int RestoreProcBreakPoint(HANDLE hp, int pid, int tid, LPVOID addr, int cmd, LPVOID param);

	int RestoreProcBreakPoint(int pid, int tid, LPVOID addr, int cmd, LPVOID param);


	int RestoreBreakPoint(int pid, int tid, LPVOID addr);

	int SetBreakPoint(LPVOID addr);

	
};


