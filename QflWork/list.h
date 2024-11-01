#pragma once


#define OffsetOf(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER )

#pragma pack(1)

typedef struct _MyListEntry {
	_MyListEntry* next;
	_MyListEntry* prev;
}MyListEntry;

#pragma pack()


class MyListClass {
	MyListEntry* m_list;
public:
	MyListClass();

	~MyListClass();

	int InsertEnd(MyListEntry* list);
	int InsertHead(MyListEntry* list);

	MyListEntry* Search(int offset,char * data,int size);

	int Remove(MyListEntry* list);
};