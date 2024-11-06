#pragma once




#pragma pack(1)

typedef struct _MyListEntry {
	_MyListEntry* next;
	_MyListEntry* prev;
}MyListEntry;

#pragma pack()


class MyListClass {
public:
	MyListEntry* m_list=0;

	int m_keyOffset;
	int m_keySize;

	MyListClass();

	~MyListClass();

	int InsertEnd(MyListEntry* list);

	int InsertHead(MyListEntry* list);

	MyListEntry* Search(int offset,char * data,int size);

	int Remove(MyListEntry* list);


};