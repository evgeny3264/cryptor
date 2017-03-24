#include "Logger.h"



Logger::Logger(std::wstring log_file_name):
	log_file(log_file_name)
{
}


Logger::~Logger()
{
	log_file.close();
}

void Logger::Log(std::wstring message)
{	
	log_file << Util::to_utf8(message) << std::endl;
	LogEdit(message+ L"\r\n");
}
