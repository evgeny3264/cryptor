#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <boost/scoped_array.hpp>
#include <ctime>
#include <boost/timer.hpp>
//������������ ���� ���������� ��� ������ � PE-�������
#include <pe_lib/pe_bliss.h>
#include <pe_lib/pe_bliss_resources.h>
//������������ ���� ��������� LZO1Z999
#include "../../lzo-2.06/include/lzo/lzo1z.h"
//������������ ���� � ������ �����������
#include "structs.h"
//������������ ���� � ����������� ������������
#include "../unpacker/parameters.h"
#include "options.h"
#include "Util.h"
#include "Logger.h"
#include "rc5.h"
#include "xor.h"
//��������� ��� ���������� � ���������� ������������ PE � LZO
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

class Protector
{
public:
	Protector(WCHAR * inFile, WCHAR * outFile, std::wstring logFile, Options);
	~Protector();
	int Protect();	
private:	
	Options options;
	WCHAR * inFile;
	WCHAR * outFile;	
	Logger logger;
	void Crypt( packed_file_info &basic_info, std::string & out_buf);
	void AntiDebug(packed_file_info &basic_info);
};

