#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <boost/scoped_array.hpp>
#include <ctime>
#include <boost/timer.hpp>
//Заголовочный файл библиотеки для работы с PE-файлами
#include <pe_lib/pe_bliss.h>
#include <pe_lib/pe_bliss_resources.h>
//Заголовочный файл алгоритма LZO1Z999
#include "../../lzo-2.06/include/lzo/lzo1z.h"
//Заголовочный файл с нашими структурами
#include "structs.h"
//Заголовочный файл с параметрами распаковщика
#include "../unpacker/parameters.h"
//Тело распаковщика (автогенеренное)
#include "unpacker.h"
#include "options.h"
#include "rc5.h"
#include "xor.h"
//Директивы для линкования с собранными библиотеками PE и LZO
#ifndef _M_X64
#ifdef _DEBUG
#pragma comment(lib, "../../pe_bliss_1.0.0/Debug/pe_bliss.lib")
#pragma comment(lib, "../Debug/lzo-2.06.lib")
#else
#pragma comment(lib, "../../pe_bliss_1.0.0/Release/pe_bliss.lib")
#pragma comment(lib, "../Release/lzo-2.06.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib, "../../pe_bliss_1.0.0/x64/Debug/pe_bliss.lib")
#pragma comment(lib, "../x64/Debug/lzo-2.06.lib")
#else
#pragma comment(lib, "../../pe_bliss_1.0.0/x64/Release/pe_bliss.lib")
#pragma comment(lib, "../x64/Release/lzo-2.06.lib")
#endif
#endif
using namespace pe_bliss;

std::string to_utf8(const std::wstring& str);
std::string to_utf8(const wchar_t* buffer, int len);
std::wstring to_wstr(char* str);
