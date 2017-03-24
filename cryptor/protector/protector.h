#pragma once
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
#include "options.h"
#include "Util.h"
#include "Logger.h"
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

class Protector
{
public:
	Protector(std::wstring  inFile, std::wstring outFile, std::wstring logFile, Options);
	~Protector();
	void Protect();
private:	
	Options options;
	std::wstring  input_file_name;
	std::wstring  output_file_name;
	Logger logger;
	bool PackData(packed_file_info &basic_info, const lzo_uint &src_length, std::string & out_buf, std::string &packed_sections_info);
	void Crypt( packed_file_info &basic_info, std::string & out_buf);
	void AntiDebug(packed_file_info &basic_info);
	bool SaveResultFile(std::wstring &base_file_name, pe_bliss::pe_base &image);
	
};

