#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include "gui.h"
#include "Util.h"

class Logger
{
public:
	Logger(std::wstring log_file_name);
	~Logger();
	void Log(std::wstring);
private:
	std::ofstream log_file;
};

