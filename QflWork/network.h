#pragma once


#include <winsock.h>
#include <iostream>

#pragma pack(1)

typedef struct  {
	char strip[16];
	int port;
}SocketAddr;


typedef struct {
	int cmd;
	char buf[256];
}NetworkCommand;

#pragma pack()

using namespace std;


class Network {
public:

	Network(int type,const char* ip, int port);
	~Network();

	static int __stdcall TcpServer(Network * instance);

	static int __stdcall UdpServer(Network* instance);

	int __stdcall UdpClient();

	int __stdcall TcpClient();

	int m_port;
	string m_ip;
	int m_type;
};