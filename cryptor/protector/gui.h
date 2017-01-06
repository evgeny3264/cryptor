#include "windows.h"
#include "resource.h"
#include <string>
#include "options.h"
#define MAX_LOADSTRING 100
INT_PTR CALLBACK	MainDlg(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK	About(HWND, UINT, WPARAM, LPARAM);
LPWSTR OpenPEFile();
LPWSTR GetOutPath();
LPCWSTR GetFileName(LPWSTR szFullPath, LPWSTR & szDir);



