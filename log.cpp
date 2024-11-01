
#include "log.h"
#include <stdio.h>

int __cdecl __log(const WCHAR* format, ...) {

	WCHAR szbuf[2048];

	va_list   pArgList;

	va_start(pArgList, format);

	int nByteWrite = vswprintf_s(szbuf, sizeof(szbuf) / sizeof(WCHAR), format, pArgList);

	va_end(pArgList);

	OutputDebugStringW(szbuf);

	wprintf(L"%S\r\n",(char*)szbuf);

	return nByteWrite;
}



int __cdecl __log(const CHAR* format, ...) {

	CHAR szbuf[2048];

	va_list   pArgList;

	va_start(pArgList, format);

	int nByteWrite = vsprintf_s(szbuf, sizeof(szbuf) / sizeof(CHAR), format, pArgList);

	va_end(pArgList);

	OutputDebugStringA(szbuf);

	printf("%s\r\n", szbuf);

	return nByteWrite;
}