#include "Util.h"



Util::Util()
{
}


Util::~Util()
{
}

std::string Util::to_utf8(const wchar_t * buffer, size_t len)
{
	int nChars = WideCharToMultiByte(
		CP_UTF8,
		0,
		buffer,
		len,
		NULL,
		0,
		NULL,
		NULL);
	if (nChars == 0) return "";

	std::string newbuffer;
	newbuffer.resize(nChars);
	WideCharToMultiByte(
		CP_UTF8,
		0,
		buffer,
		len,
		const_cast< char* >(newbuffer.c_str()),
		nChars,
		NULL,
		NULL);

	return newbuffer;
}

std::string Util::to_utf8(const std::wstring & str)
{
	return to_utf8(str.c_str(), str.size());
}

std::wstring Util::StringToWstring(std::string str)
{	
	std::wstring ws;
	copy(str.begin(), str.end(), std::back_inserter(ws));
	return ws;
}


