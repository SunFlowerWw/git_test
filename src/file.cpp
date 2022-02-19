#include <Windows.h>
#include "../inc/file.h"
#include "../inc/bbuf.h"

DWORD Fs::static_last_error = 0;

Fs::Fs(LPCTSTR path)
{
	h_file = CreateFile(path, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

Fs::~Fs()
{
	CloseHandle(h_file);
}

DWORD Fs::size()
{
	return GetFileSize(h_file, NULL);
}

DWORD Fs::size(LPCTSTR path)
{
	DWORD ret = 0;
	HANDLE h_file = CreateFile(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	ret = GetFileSize(h_file, NULL);
	CloseHandle(h_file);
	return ret;
}

bool Fs::cp(LPCTSTR src_path, LPTSTR dst_path, BOOL overwrite)
{
	BOOL ret = FALSE;
	ret = CopyFile(src_path, dst_path, overwrite);
	if (!ret)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	return ret;
}

bool Fs::mv(LPCTSTR src_path, LPTSTR dst_path)
{
	BOOL ret = FALSE;
	ret = MoveFile(src_path, dst_path);
	if (!ret)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	return ret;
}

bool Fs::rm(LPCTSTR path)
{
	BOOL ret = FALSE;
	DWORD attr = INVALID_FILE_ATTRIBUTES;
	attr = GetFileAttributes(path);
	
	switch (attr) {
	case INVALID_FILE_ATTRIBUTES:
		break;
	case FILE_ATTRIBUTE_DIRECTORY:
		ret = RemoveDirectory(path);
		break;
	default:
		ret = DeleteFile(path);
		break;
	}

	if (!ret)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	
	return ret;
}

bool Fs::md(LPCTSTR path)
{
	BOOL ret = FALSE;
	ret = CreateDirectory(path, NULL);
	if (!ret)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	return ret;
}

bool Fs::sh(LPCTSTR path, LPCTSTR param)
{
	BOOL ret = FALSE;
	SHELLEXECUTEINFO se = {};
	se.cbSize = sizeof(SHELLEXECUTEINFO);
	se.lpFile = path;
	se.lpParameters = param;
	se.nShow = SW_HIDE;
	se.hwnd = NULL;
	se.lpDirectory = NULL;
	ret = ShellExecuteEx(&se);
	if (!ret)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	return ret;
}

bool Fs::is_file(LPCTSTR path)
{
	DWORD attr = GetFileAttributes(path);
	if (attr == INVALID_FILE_ATTRIBUTES)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	return INVALID_FILE_ATTRIBUTES != attr && 0 == (attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool Fs::is_dir(LPCTSTR path)
{
	DWORD attr = GetFileAttributes(path);
	if (attr == INVALID_FILE_ATTRIBUTES)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	return INVALID_FILE_ATTRIBUTES != attr && 0 != (attr & FILE_ATTRIBUTE_DIRECTORY);
}

//bbuf Fs::rd(LPCTSTR path, LPCTSTR flag)
//{
//	
//	return bbuf();
//}
//
//bbuf Fs::wt(LPCTSTR path, LPCTSTR flag)
//{
//
//	return bbuf();
//}
