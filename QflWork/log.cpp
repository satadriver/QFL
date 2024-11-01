
#include "log.h"
#include <stdio.h>

int __cdecl log(const WCHAR* format, ...) {

	WCHAR szbuf[2048];

	va_list   pArgList;

	va_start(pArgList, format);

	int nByteWrite = vswprintf_s(szbuf, sizeof(szbuf) / sizeof(WCHAR), format, pArgList);

	va_end(pArgList);

	OutputDebugStringW(szbuf);

	return nByteWrite;
}



int __cdecl log(const CHAR* format, ...) {

	CHAR szbuf[2048];

	va_list   pArgList;

	va_start(pArgList, format);

	int nByteWrite = vsprintf_s(szbuf, sizeof(szbuf) / sizeof(CHAR), format, pArgList);

	va_end(pArgList);

	OutputDebugStringA(szbuf);

	return nByteWrite;
}