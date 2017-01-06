struct options
{
	bool force_mode;
	bool strip_dos_headers;
	bool rc5;
	bool anti_debug;
	bool crypt;
	bool rebuild_load_config;

};
void LogEdit(std::wstring str);
int protect(WCHAR * inFile, WCHAR * outFile, WCHAR * logFile, options);