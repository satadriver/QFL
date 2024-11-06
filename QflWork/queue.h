#pragma once

#include <Windows.h>

#define QUEUE_VOLUME_LIMIT 0X1000

#pragma pack(1)

typedef struct  {
	int head;
	int tail;
	LPVOID e[QUEUE_VOLUME_LIMIT];
}CircleQueue;

#pragma pack()



class QueueClass {

public:
	QueueClass();

	~QueueClass();

	CircleQueue * m_queue = 0;

	int Enqueue(LPVOID v);
	int Dequeue(LPVOID* v);

	int Size();
};