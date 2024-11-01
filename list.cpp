
#include "list.h"
#include <Windows.h>







MyListClass::MyListClass() {
	m_list = new MyListEntry;
	m_list->next = 0;
	m_list->prev = 0;
	m_keyOffset = 0;
	m_keySize = 0;
}


MyListClass::~MyListClass() {

	MyListEntry* n = m_list->next;
	MyListEntry* b = n;

	do
	{
		if (n == 0) {
			break;
		}

		MyListEntry* t = n;
		n = n->next;
		delete t;
	} while (n != b);

	if (m_list) {
		delete m_list;
	}
}


MyListEntry* MyListClass::Search(int offset,char * data,int size) {
	if (data == 0 || size == 0) {
		return 0;
	}

	MyListEntry* n = m_list->next;
	MyListEntry* b = n;

	do
	{
		if (n == 0) {
			return 0;
		}
		char* obj = (char*)((char*)n + offset);
		if (memcmp(data, obj,size) == 0) {
			return n;
		}
		n = n->next;

	} while (n != b);

	return 0;
}





int MyListClass::InsertHead(MyListEntry* list) {
	if (list == 0) {
		return 0;
	}
	MyListEntry* n = m_list->next;
	MyListEntry* p = m_list->prev;

	if (n == 0 || p == 0) {
		m_list->next = list;
		m_list->prev = list;

		list->prev = list;
		list->next = list;
		return 0;
	}

	p->next = list;
	n->prev = list;

	list->prev = p;
	list->next = n;

	m_list->next = list;

	return TRUE;
}

int MyListClass::InsertEnd(MyListEntry* list) {
	if (list == 0) {
		return 0;
	}

	MyListEntry* n = m_list->next;
	MyListEntry* p = m_list->prev;

	if (n == 0 || p == 0) {
		m_list->next = list;
		m_list->prev = list;
		list->next = list;
		list->prev = list;
		return TRUE;
	}

	p->next = list;
	n->prev = list;

	list->prev = p;
	list->next = n;

	m_list->prev = list;

	return TRUE;
}


int MyListClass::Remove(MyListEntry* list) {
	if (list == 0 || list == m_list) {
		return 0;
	}

	if (list == m_list->next) {
		MyListEntry* n = m_list->next->next;
		MyListEntry* p = m_list->prev;
		if (p == n) {
			m_list->next = 0;
			m_list->prev = 0;
		}
		else {
			m_list->next = n;
			n->prev = p;
			p->next = n;
		}
		delete list;
		
		return TRUE;
	}
	else if (list == m_list->prev) {
		MyListEntry* n = m_list->next;
		MyListEntry* p = m_list->prev->prev;
		if (p == n) {
			m_list->next = 0;
			m_list->prev = 0;
		}
		else {
			m_list->prev = p;
			n->prev = p;
			p->next = n;
		}
		delete list;

		return TRUE;
	}

	MyListEntry* n = m_list->next;
	MyListEntry* b = n;
	do
	{
		if (list == n) {
			MyListEntry* prev = n->prev;
			MyListEntry* next = n->next;
			prev->next = next;
			next->prev = prev;
			delete list;
			break;
		}
		n = n->next;
	} while (n != b);

	return TRUE;
}