#pragma once
#include <string>
#include <Windows.h>
#include "options.h"
#include <algorithm>
#include <iterator> 
class Util final
{
public:
	Util();
	~Util();
	static std::string to_utf8(const wchar_t * buffer, size_t len);	
	static std::string to_utf8(const std::wstring& str);	
	static std::wstring StringToWstring(std::string);
};

