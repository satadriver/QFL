
#include <winsock.h>
#include <iostream>
#include "network.h"

using namespace std;



#pragma comment(lib,"ws2_32.lib")


Network::Network(int type,const char * ip,int port) {
	WSADATA wsa = { 0 };
	int ret = WSAStartup(0x0202, &wsa);
	if (ret) {
		perror("WSAStartup error\r\n");
	}
	m_ip = ip;
	m_port = port;
	m_type = type;
}


Network::~Network() {

}


int __stdcall Network::UdpServer(Network* instance) {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(instance->m_ip.c_str());
	sa.sin_port = ntohs(instance->m_port);

	ret = bind(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret == INVALID_SOCKET) {
		perror("bind\r\n");
		return -1;
	}

	while (1) {
		sockaddr_in saClient = { 0 };
		char recvbuf[1024];
		int addrsize = sizeof(sockaddr_in);
		int recvlen = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (sockaddr*)&saClient, &addrsize);
		if (recvlen > 0) {
			recvbuf[recvlen] = 0;
			printf("%s\r\n", recvbuf);
		}
		else {
			perror("recvfrom error\r\n");
		}
	}

	closesocket(s);

	return 0;
}

int __stdcall Network::UdpClient() {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(m_ip.c_str());
	sa.sin_port = ntohs(m_port);

	int sendsize = 1024;
	char sendbuf[1024];
	memset(sendbuf, 0x41, sendsize);

	const char* content = "hello,how are you?";
	lstrcpyA(sendbuf, content);

	ret = sendto(s, (char*)sendbuf, lstrlenA(content) + 1, 0, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret > 0) {
		int addrsize = sizeof(sockaddr_in);
		sockaddr_in saClient = { 0 };
		int recvlen = recvfrom(s, sendbuf, sendsize, 0, (sockaddr*)&saClient, &addrsize);
		if (recvlen > 0) {
			sendbuf[recvlen] = 0;
			printf("%s\r\n", sendbuf);
		}
		else {
			perror("recvfrom error\r\n");
		}
	}
	else {
		perror("sendto error\r\n");
	}

	closesocket(s);

	return 0;
}

int __stdcall Network::TcpClient() {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		perror("socket error\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = inet_addr(m_ip.c_str());
	sa.sin_port = ntohs(m_port);

	ret = connect(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	int bufsize = 0x1000;
	char* sendbuf = new char[bufsize];
	memset(sendbuf, 0x41, bufsize);

	while (1) {
		const char* str = "hello, how are you?";
		lstrcpyA(sendbuf, str);
		ret = send(s, (char*)sendbuf, lstrlenA(str) + 1, 0);
		if (ret > 0) {

		}

		ret = recv(s, sendbuf, bufsize, 0);
		if (ret > 0) {
			sendbuf[ret] = 0;
			printf("%s\r\n", sendbuf);
		}

		Sleep(1000);
	}


	return 0;
}


int __stdcall Network::TcpServer(Network* instance) {

	int ret = 0;

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		perror("socket\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_addr.S_un.S_addr = INADDR_ANY;
	sa.sin_port = ntohs(instance->m_port);

	ret = bind(s, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret == INVALID_SOCKET) {
		perror("bind\r\n");
		return -1;
	}
	ret = listen(s, 16);

	while (1) {
		sockaddr_in client;
		int csize = sizeof(sockaddr_in);
		SOCKET sc = accept(s, (sockaddr*)&client, &csize);
		if (sc != INVALID_SOCKET) {
			while (1) {
				char recvbuf[0x1000];
				int recvlen = recv(sc, recvbuf, 0x1000, 0);
				if (recvlen <= 0) {
					closesocket(sc);
					break;
				}
				recvbuf[recvlen] = 0;

				const char* data = "fine,thank you,and you ?";
				ret = send(sc, data, lstrlenA(data)+1, 0);
			}
		}
		else {
			continue;
		}
	}
	return 0;
}
