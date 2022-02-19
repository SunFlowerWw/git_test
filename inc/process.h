#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <winternl.h>

#include "bbuf.h"

class Ps
{
public:
	static DWORD static_last_error;
public:
	Ps();
	Ps(DWORD pid);
	Ps(LPCTSTR path);
	~Ps();

	PVOID alloc(SIZE_T size);
	bool free(PVOID addr);
	
	BBuf rdm(PVOID addr, SIZE_T size);
	void wtm(PVOID addr, const BBuf& bbuf);
	void wtm(PVOID dst_addr, PVOID src_addr, SIZE_T size);

	template<typename T>
	T rdm(PVOID addr) {
		auto bbuf = rdm(addr, sizeof(T));
		return *(T*)bbuf.data();
	}

	template<typename T>
	void wtm(PVOID addr, const T& val) {
		BBuf bbuf(&val, sizeof(T));
		wtm(addr, bbuf);
	}

	DWORD vprot(PVOID addr, SIZE_T size, DWORD prot = PAGE_EXECUTE_READWRITE);
	DWORD vprot(PVOID addr, DWORD prot = PAGE_EXECUTE_READWRITE);

	HANDLE crt(PVOID base, PVOID param = NULL, DWORD flag = 0);
	HINSTANCE ld(LPCTSTR name);
	PVOID sym(LPCTSTR mod_name, LPCSTR sym_name = NULL);

	bool dump(LPCTSTR path = NULL);
	DWORD wait(DWORD ms = INFINITE);
	bool ed();
	bool x86();
	bool x64();
	SIZE_T peb();

	DWORD err() {
		DWORD ret = last_error;
		last_error = 0;
		return ret;
	}

	static DWORD g_err() {
		DWORD ret = static_last_error;
		static_last_error = 0;
		return ret;
	}

	static DWORD id(LPCTSTR proc_name);
	static void kill(LPCTSTR proc_name);
	static bool kill(DWORD pid);
	static DWORD wait(HANDLE h_obj, DWORD ms = INFINITE);
	static void sleep(DWORD ms);
	static bool dbg();
	static bool uac();

private:
	NTSTATUS _NtQueryInformationProcess(
		HANDLE hProcess,
		PROCESSINFOCLASS pic,
		PVOID pPI,
		ULONG cbSize,
		PULONG pLength
	);

private:
	HANDLE h_proc = NULL;
	HANDLE h_thread = NULL;
	DWORD pid = 0;
	DWORD tid = 0;
	DWORD last_error = 0;
};