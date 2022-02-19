#pragma once

class Fs
{
private:
	static DWORD static_last_error;
public:
	Fs(LPCTSTR path);
	~Fs();

	DWORD err() {
		DWORD ret = last_error;
		last_error = 0;
		return ret;
	}
	DWORD size();

	static DWORD g_err() {
		DWORD ret = static_last_error;
		static_last_error = 0;
		return ret;
	}

	static DWORD size(LPCTSTR path);
	static bool cp(LPCTSTR src_path, LPTSTR dst_path, BOOL overwrite = FALSE);
	static bool mv(LPCTSTR src_path, LPTSTR dst_path);
	static bool rm(LPCTSTR path);
	static bool md(LPCTSTR path);
	static bool sh(LPCTSTR path, LPCTSTR param = NULL);
	static bool is_file(LPCTSTR path);
	static bool is_dir(LPCTSTR path);
	/*static bbuf rd(LPCTSTR path, LPCTSTR flag = TEXT("rb"));
	static bbuf wt(LPCTSTR path, LPCTSTR flag = TEXT("rb"));*/

private:
	HANDLE h_file = NULL;
	DWORD last_error = 0;
};