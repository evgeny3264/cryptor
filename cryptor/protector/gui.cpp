#include "gui.h"

HWND hEditIn;
HWND hEditOut;
HWND hEditLog;
HWND hTextLog;

HINSTANCE hInst;
options opt;
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:{
		HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI5));
		SendMessage(hDlg, WM_SETICON, 1, (LPARAM)hIcon);
		return (INT_PTR)TRUE;
	}

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
INT_PTR CALLBACK MainDlg(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	
	LPCWSTR szFileName;
	LPWSTR szDir;
	LPWSTR szPathIn;
	LPWSTR szPathOut;
	LPWSTR szPathLog;
	
	
	switch (message)
	{
	case WM_INITDIALOG:{
		HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI5));
		SendMessage(hDlg, WM_SETICON, 1, (LPARAM)hIcon);
		HMENU hMenu = LoadMenu(hInst, MAKEINTRESOURCE(105));
		SetMenu(hDlg, hMenu);
		hEditIn = GetDlgItem(hDlg, IDE_IN);
		hEditOut = GetDlgItem(hDlg, IDE_OUT);
		hEditLog = GetDlgItem(hDlg, IDE_LOG);
		hTextLog = GetDlgItem(hDlg, IDT_LOG);		
		CheckDlgButton(hDlg, IDC_SDH, BST_CHECKED);
		CheckDlgButton(hDlg, IDC_AD, BST_CHECKED);
		CheckDlgButton(hDlg, IDC_CRYPT, BST_CHECKED);
		CheckDlgButton(hDlg, IDC_RC5, BST_CHECKED);
		return (INT_PTR)TRUE;
	}
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDOK:
		{
			
			szPathIn = new WCHAR[MAX_PATH];
			SendMessage(hEditIn, WM_GETTEXT, MAX_PATH, (LPARAM)szPathIn);
			szPathOut = new WCHAR[MAX_PATH];
			SendMessage(hEditOut, WM_GETTEXT, MAX_PATH, (LPARAM)szPathOut);
			szPathLog = new WCHAR[MAX_PATH];
			SendMessage(hEditLog, WM_GETTEXT, MAX_PATH, (LPARAM)szPathLog);
			opt.force_mode = IsDlgButtonChecked(hDlg, IDC_FORCE);
			opt.strip_dos_headers = IsDlgButtonChecked(hDlg, IDC_SDH);
			opt.crypt = IsDlgButtonChecked(hDlg, IDC_CRYPT);
			opt.rc5 = IsDlgButtonChecked(hDlg, IDC_RC5);
			opt.anti_debug = IsDlgButtonChecked(hDlg, IDC_AD);
			opt.rebuild_load_config = IsDlgButtonChecked(hDlg, IDC_RLG);
			protect(szPathIn, szPathOut, szPathLog,opt);
			delete[] szPathIn;
			delete[] szPathOut;
			delete[] szPathLog;
			
			break;
		}
		case IDC_CRYPT:
		{
			
			EnableWindow(GetDlgItem(hDlg, IDC_RC5), IsDlgButtonChecked(hDlg, IDC_CRYPT));	

			break;
		}
		case IDB_IN:
		{
			szPathIn = OpenPEFile();
			SendMessage(hEditIn, WM_SETTEXT, 0, (LPARAM)szPathIn);
			SetFocus(hEditIn);
			szFileName=GetFileName(szPathIn,szDir);
			delete[] szPathIn;
			szPathOut = new WCHAR[MAX_PATH];
			wcscpy_s(szPathOut, MAX_PATH, szDir);			
			wcscat_s(szPathOut, MAX_PATH, szFileName);
			//wcscat_s(szPathOut, MAX_PATH, L"_p");
			SendMessage(hEditOut, WM_SETTEXT, 0, (LPARAM)szPathOut);
			delete[] szPathOut;
			szPathLog = new WCHAR[MAX_PATH];
			wcscpy_s(szPathLog, MAX_PATH, szDir);
			wcscat_s(szPathLog, MAX_PATH, L"protect_log.txt");
			SendMessage(hEditLog, WM_SETTEXT, 0, (LPARAM)szPathLog);
			delete[] szPathLog;	
			delete[] szDir;
			delete[] szFileName;
			break;
		}
		case IDB_OUT:
		{
			szPathOut=GetOutPath();
			SendMessage(hEditOut, WM_SETTEXT, 0, (LPARAM)szPathOut);
			delete[] szPathOut;
			break;
		}
		case IDB_LOG:
		{
			szPathLog = GetOutPath();
			SendMessage(hEditLog, WM_SETTEXT, 0, (LPARAM)szPathLog);
			delete[] szPathLog;
			break;
		}
		case ID_HELP_ABOUT:
			DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_ABOUT), hDlg, About, 0);
			break;
		case ID_FILE_EXIT:
			EndDialog(hDlg, 0);
			break;
		case ID_FILE_OPEN:
			SendMessage(hDlg, WM_COMMAND, IDB_IN, 0);
			break;
		default:
			break;
		}
		break;
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		break;
	}
	return (INT_PTR)FALSE;
}

int CALLBACK WinMain( HINSTANCE hInstance,
	 HINSTANCE hPrevInstance,
	 LPSTR    lpCmdLine,
	 int       nCmdShow)
{
	hInst = hInstance;	
	DialogBoxParam(hInstance, MAKEINTRESOURCE(IDD_MAIN),0, MainDlg, 0);
	return 0;

}

LPCWSTR GetFileName(LPWSTR szFullPath, LPWSTR & szDir)
{
	std::wstring  base_file_name(szFullPath);
	std::wstring dir_name;
	std::string::size_type slash_pos;
	if ((slash_pos = base_file_name.find_last_of(L"/\\")) != std::wstring::npos)
	{
		dir_name = base_file_name.substr(0, slash_pos + 1); //Директория исходного файла
		base_file_name = base_file_name.substr(slash_pos + 1); //Имя исходного файла
	}
	LPWSTR szFileName = new WCHAR[100];
	szDir = new WCHAR[MAX_PATH];
	wcscpy_s(szDir, MAX_PATH, dir_name.c_str());
	wcscpy_s(szFileName, 100, base_file_name.c_str());
	return szFileName;
}

LPWSTR GetOutPath()
{

	OPENFILENAME ofn;       // структура станд. блока диалога
	LPWSTR lszFile = new WCHAR[MAX_PATH];       // буфер для имени файла	
	// Инициализация структуры OPENFILENAME
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = lszFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = MAX_PATH * 2;
	ofn.lpstrFilter = L"Supported Files(*.exe, *.dll, *.txt)\0*.exe;*.dll;*.txt\0";;
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	// Показываем на экране диалоговое окно Открыть (Open).

	if (GetSaveFileName(&ofn) == TRUE){
		return ofn.lpstrFile;
	}
	lszFile[0] = '\0';
	return lszFile;
}

LPWSTR OpenPEFile()
{
	OPENFILENAME ofn;       // структура станд. блока диалога
	LPWSTR lszFile = new WCHAR[MAX_PATH];       // буфер для имени файла	
	// Инициализация структуры OPENFILENAME
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = lszFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = MAX_PATH * 2;
	ofn.lpstrFilter = L"Supported Files(*.exe, *.dll)\0*.exe;*.dll\0";;
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	// Показываем на экране диалоговое окно Открыть (Open).

	if (GetOpenFileName(&ofn) == TRUE){		
		return ofn.lpstrFile;
	}
	lszFile[0] = '\0';
	return lszFile;
}

void LogEdit(std::wstring str)
{
	int index = GetWindowTextLength(hTextLog);
	SendMessage(hTextLog, EM_SETSEL, (WPARAM)index, (LPARAM)index); // set selection - end of text
	SendMessage(hTextLog, EM_REPLACESEL, 0, (LPARAM)str.c_str());
}