
#include "list.h"
#include <Windows.h>


MyListClass::MyListClass() {
	m_list = new MyListEntry;
	m_list->next = 0;
	m_list->prev = 0;
}


MyListClass::~MyListClass() {
	MyListEntry* f = m_list->next;
	MyListEntry* b = f;
	do
	{
		MyListEntry* t = f;
		
		f = f->next;
		delete t;
	} while (f != b);

	if (m_list) {
		delete m_list;
	}
}


MyListEntry* MyListClass::Search(int offset,char * data,int size) {

	MyListEntry* f = m_list->next;
	MyListEntry* b = f;
	
	do
	{
		char* target = (char*)((char*)f + offset);
		if (memcmp(data,target,size) == 0) {
			return f;
		}
		f = f->next;
	} while (f != b);

	return 0;
}


int MyListClass::InsertHead(MyListEntry* list) {
	MyListEntry* f = m_list->next;
	MyListEntry* p = m_list->prev;

	if (f == 0 || p == 0) {
		m_list->next = list;
		m_list->prev = list;
		list->prev = list;
		list->next = list;
		return 0;
	}

	p->next = list;
	f->prev = list;

	list->prev = p;
	list->next = f;

	m_list->next = list;

	return 0;
}

int MyListClass::InsertEnd(MyListEntry* list) {
	MyListEntry* f = m_list->next;
	
	MyListEntry* p = m_list->prev;

	if (f == 0 || p == 0) {
		m_list->next = list;
		m_list->prev = list;
		list->prev = list;
		list->next = list;
		return 0;
	}

	p->next = list;
	f->prev = list;

	list->prev = p;
	list->next = f;

	m_list->prev = list;

	return 0;
}


int MyListClass::Remove(MyListEntry* list) {
	if (list == m_list->next) {
		MyListEntry* n = m_list->next;
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
		
		return 0;
	}

	MyListEntry* f = m_list->next;
	MyListEntry* b = f;
	do
	{
		if (list == f) {
			MyListEntry* p = f->prev;
			MyListEntry* n = f->next;
			p->next = n;
			n->prev = p;
			delete list;
			break;
		}
		f = f->next;
	} while (f != b);

	return 0;
}