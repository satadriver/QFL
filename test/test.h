#pragma once


#include <winsock.h>
#include <iostream>

#pragma pack(1)

typedef struct  {
	char strip[16];
	int port;
}SocketAddr;

#pragma pack()

using namespace std;

int __stdcall testUdpServer(string ip, int port);

int __stdcall testUdpClient(string ip, int port);

int __stdcall testClient(string ip, int port);

int __stdcall testServer();