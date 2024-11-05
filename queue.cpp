

#include "queue.h"

QueueClass::QueueClass() {
	if (m_queue == 0) {
		m_queue = new CircleQueue();
		m_queue->head = 0;
		m_queue->tail = 0;
	}
}


QueueClass::~QueueClass() {
	if (m_queue) {
		delete m_queue;
	}
}

int QueueClass::Dequeue(LPVOID * v) {
	if (m_queue->tail == m_queue->head)
	{
		return 0;
	}

	*v = m_queue->e[m_queue->head];

	m_queue->head ++;
	if (m_queue->head >= QUEUE_VOLUME_LIMIT) {
		m_queue->head = 0;
	}
	
	return TRUE;
}


int QueueClass::Enqueue(LPVOID v) {

	if (m_queue->tail + 1 == QUEUE_VOLUME_LIMIT) {
		if ( m_queue->head == 0) {
			return 0;
		}
		else {
			m_queue->e[m_queue->tail] = v;
			m_queue->tail = 0;
		}
	}
	else {
		if (m_queue->tail + 1 == m_queue->head) {
			return 0;
		}
		else {
			m_queue->e[m_queue->tail] = v;
			m_queue->tail++;
		}
	}

	return TRUE;
}


int QueueClass::Size() {
	if (m_queue->tail > m_queue->head) {
		return m_queue->tail - m_queue->head;
	}
	else {
		return QUEUE_VOLUME_LIMIT - (m_queue->head - m_queue->tail);
	}
}