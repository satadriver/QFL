#pragma once

#include <Windows.h>
#include "list.h"

#pragma pack(1)

typedef struct {
	MyListEntry  list;
	unsigned char * addr;
	unsigned char code;
	int pid;
	int tid;
}BreakPointNode;

#pragma pack()


int RestoreBreakPoint(LPVOID addr);

int SetBreakPoint(LPVOID addr);