#include <Windows.h>
#include <Dbghelp.h>
#include <Psapi.h>

#include "../inc/process.h"
#include "../inc/bbuf.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Advapi32.lib")

DWORD Ps::static_last_error = 0;

Ps::Ps()
{
	h_proc = GetCurrentProcess();
	pid = GetCurrentProcessId();
}

Ps::Ps(DWORD pid)
{
	h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h_proc)
		throw GetLastError();
	this->pid = pid;
}

Ps::Ps(LPCTSTR path)
{
	BOOL ret = FALSE;
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	TCHAR path_buf[256] = { 0 };

	wsprintf(path_buf, _T("%s"), path);

	ret = CreateProcess(NULL, path_buf, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (!ret)
		throw GetLastError();
	h_proc = pi.hProcess;
	h_thread = pi.hThread;
	pid = pi.dwProcessId;
	tid = pi.dwThreadId;
}

Ps::~Ps()
{
	CloseHandle(h_proc);
	if (h_thread) {
		CloseHandle(h_thread);
	}
}

DWORD Ps::id(LPCTSTR proc_name)
{
	DWORD ret = -1;
	PROCESSENTRY32	pe32 = { 0 };
	BOOL exist = FALSE;
	HANDLE snapshot;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return -1;

	exist = Process32First(snapshot, &pe32);
	while (exist)
	{
		if (_tcsicmp(proc_name, pe32.szExeFile) == 0)
		{
			ret = pe32.th32ProcessID;
			break;
		}

		exist = Process32Next(snapshot, &pe32);
	}

	CloseHandle(snapshot);

	return ret;
}

PVOID Ps::sym(LPCTSTR mod_name, LPCSTR sym_name)
{
	if (pid == GetCurrentProcessId()) {
		PVOID sym_addr = NULL;
		HMODULE h_mod = GetModuleHandle(mod_name);

		if (!h_mod)
			last_error = GetLastError();
		else
			last_error = 0;

		if (!sym_name) {
			return h_mod;
		}

		sym_addr = (PVOID)GetProcAddress(h_mod, sym_name);

		if (!sym_addr)
			last_error = GetLastError();
		else
			last_error = 0;
		return sym_addr;
	}
	else {
		PVOID sym_addr = NULL;

		auto mod_name_addr = alloc(_tcslen(mod_name) * 2 + 2);
		wtm(mod_name_addr, (PVOID)mod_name, _tcslen(mod_name) * 2 + 2);
		HANDLE h_rt = crt(&GetModuleHandle, mod_name_addr);
		Ps::wait(h_rt);
		free(mod_name_addr);

		DWORD h_mod_low = 0;
		HMODULE h_mod = NULL;
		GetExitCodeThread(h_rt, &h_mod_low);
		if (!h_mod_low)
			return NULL;

		HMODULE h_mods[1024] = {0};
		DWORD cb_needed;

		if (EnumProcessModules(h_proc, h_mods, sizeof(h_mods), &cb_needed)) {
			for (int i = 0; i < cb_needed / sizeof(HMODULE); i++) {
				if (*(PDWORD)&h_mods[i] == h_mod_low) {
					h_mod = h_mods[i];
				}
			}
		}

		if (!sym_name) {
			return h_mod;
		}

		TCHAR full_mod_name[MAX_PATH];
		GetModuleFileNameEx(h_proc, h_mod, full_mod_name, MAX_PATH);

		HINSTANCE h_tmp_mod = LoadLibrary(full_mod_name);
		sym_addr = GetProcAddress(h_tmp_mod, sym_name);
		if (!sym_addr)
			last_error = GetLastError();
		else
			last_error = 0;
		FreeLibrary(h_tmp_mod);
		return (PVOID)((SIZE_T)sym_addr - (SIZE_T)h_tmp_mod + (SIZE_T)h_mod);
	}
}

void Ps::kill(LPCTSTR proc_name)
{
	PROCESSENTRY32	pe32 = { 0 };
	BOOL exist = FALSE;
	DWORD kill_cur_pid = 0;
	HANDLE snapshot;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return;

	exist = Process32First(snapshot, &pe32);
	while (exist)
	{
		if (_tcsicmp(proc_name, pe32.szExeFile) == 0)
		{
			if (pe32.th32ProcessID == GetCurrentProcessId()) {
				kill_cur_pid = GetCurrentProcessId();
			}
			else {
				Ps::kill(pe32.th32ProcessID);
			}
		}

		exist = Process32Next(snapshot, &pe32);
	}

	CloseHandle(snapshot);
	if (kill_cur_pid)
		Ps::kill(kill_cur_pid);
	return;
}

bool Ps::kill(DWORD pid)
{
	BOOL ret = FALSE;
	HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (h_proc) {
		ret = TerminateProcess(h_proc, 0);
	}
	if (!ret)
		static_last_error = GetLastError();
	else
		static_last_error = 0;
	return ret;
}

DWORD Ps::wait(HANDLE h_obj, DWORD ms)
{
	DWORD ret = WaitForSingleObject(h_obj, ms);
	return ret;
}

void Ps::sleep(DWORD ms)
{
	Sleep(ms);
}

bool Ps::dbg()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return   FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		return false;
	}
	return true;
}

bool Ps::uac()
{
	return false;
}

DWORD Ps::vprot(PVOID addr, SIZE_T size, DWORD prot)
{

	DWORD old_prot = 0;
	BOOL ret = FALSE;
	ret = VirtualProtectEx(h_proc, addr, size, prot, &old_prot);
	if (!ret)
		last_error = GetLastError();
	else
		last_error = 0;
	return old_prot;
}

DWORD Ps::vprot(PVOID addr, DWORD prot)
{
	return vprot(addr, 1, prot);
}

HANDLE Ps::crt(PVOID base, PVOID param, DWORD flag)
{
	DWORD r_tid = 0;
	HANDLE ret = NULL;
	ret = CreateRemoteThread(h_proc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(base), param, flag, &r_tid);
	if (!ret)
		last_error = GetLastError();
	else
		last_error = 0;
	return ret;
}

HINSTANCE Ps::ld(LPCTSTR name)
{
	HINSTANCE h_mod = NULL;
	if (pid == GetCurrentProcessId()) {
		h_mod = LoadLibrary(name);
		if (!h_mod)
			last_error = GetLastError();
		else
			last_error = 0;
	}
	else {
		auto name_addr = alloc(_tcslen(name) * 2 + 2);
		wtm(name_addr, (PVOID)name, _tcslen(name) * 2 + 2);
		HANDLE h_rt = crt(&LoadLibrary, name_addr);
		Ps::wait(h_rt);
		free(name_addr);

		DWORD h_mod_low;
		GetExitCodeThread(h_rt, &h_mod_low);

		HMODULE h_mods[1024];
		DWORD cb_needed;

		if (EnumProcessModules(h_proc, h_mods, sizeof(h_mods), &cb_needed)) {
			for (int i = 0; i < cb_needed / sizeof(HMODULE); i++) {
				if (*(PDWORD)&h_mods[i] == h_mod_low) {
					h_mod = h_mods[i];
				}
			}
		}
	}
	return h_mod;
}

bool Ps::dump(LPCTSTR path)
{
	bool ret=false;
	TCHAR buf[30];
	HANDLE h_file=NULL;
	DWORD pid = GetProcessId(h_proc);

	if (path)
		h_file = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	else {
		wsprintf(buf, _T("%d.dmp"), pid);
		h_file = CreateFile(buf, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	}

	ret = MiniDumpWriteDump(h_proc,
		pid,
		h_file,
		MiniDumpWithFullMemory,
		NULL,
		NULL,
		NULL);
	if (!ret)
		last_error = GetLastError();
	else
		last_error = 0;
	CloseHandle(h_file);
	return ret;
}

DWORD Ps::wait(DWORD ms)
{
	DWORD ret = WAIT_FAILED;
	ret = WaitForSingleObject(h_proc, ms);
	if (ret == WAIT_FAILED)
		last_error = GetLastError();
	else
		last_error = 0;
	return ret;
}

bool Ps::ed()
{
	BOOL ret = FALSE;
	ret = TerminateProcess(h_proc, 0);
	if (!ret)
		last_error = GetLastError();
	else
		last_error = 0;
	return ret;
}

bool Ps::x86()
{
	BOOL bIsWow64 = FALSE;

	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(h_proc, &bIsWow64))
		{
			//handle error
		}
	}

	SYSTEM_INFO systemInfo = { 0 };
	GetNativeSystemInfo(&systemInfo);

	// x86 environment
	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		return true;

	// Check if the process is an x86 process that is running on x64 environment.
	// IsWow64 returns true if the process is an x86 process
	return bIsWow64;
}

bool Ps::x64()
{
	return !x86();
}

SIZE_T Ps::peb()
{
	int   iReturn = 1;
	DWORD dwSize;

	PROCESS_BASIC_INFORMATION  pbi;

	iReturn =
		_NtQueryInformationProcess(
			h_proc, ProcessBasicInformation, &pbi, sizeof(pbi), &dwSize);

	if (iReturn >= 0)
		return (SIZE_T)pbi.PebBaseAddress;
	else
		return NULL;
}

PVOID Ps::alloc(SIZE_T size)
{
	return VirtualAllocEx(h_proc, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

bool Ps::free(PVOID addr)
{
	return VirtualFreeEx(h_proc, addr, 0, MEM_RELEASE);
}

BBuf Ps::rdm(PVOID addr, SIZE_T size)
{
	BOOL ret = FALSE;
	BBuf bbuf(size);
	SIZE_T number_of_bytes_read = 0;

	bbuf.resize(size);

	ret = ReadProcessMemory(h_proc, addr, bbuf.data(), size, &number_of_bytes_read);
	if (!ret)
		last_error = GetLastError();
	else
		last_error = 0;
	if (number_of_bytes_read - size)
		bbuf.resize(0);
	return bbuf;
}

void Ps::wtm(PVOID addr, const BBuf& bbuf)
{
	BOOL ret = FALSE;
	SIZE_T number_of_bytes_written = 0;

	ret = WriteProcessMemory(h_proc, addr, const_cast<BBuf&>(bbuf).data(), bbuf.size(), &number_of_bytes_written);
	if (!ret)
		last_error = GetLastError();
	else
		last_error = 0;
}

void Ps::wtm(PVOID dst_addr, PVOID src_addr, SIZE_T size)
{
	BOOL ret = FALSE;
	SIZE_T number_of_bytes_written = 0;

	ret = WriteProcessMemory(h_proc, dst_addr, src_addr, size, &number_of_bytes_written);
	if (!ret)
		last_error = GetLastError();
	else
		last_error = 0;
}

NTSTATUS Ps::_NtQueryInformationProcess(HANDLE hProcess, PROCESSINFOCLASS pic, PVOID pPI, ULONG cbSize, PULONG pLength)
{
	typedef NTSTATUS(CALLBACK* PFN_NTQUERYINFORMATIONPROCESS)(
		HANDLE ProcessHandle,
		PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation,
		ULONG ProcessInformationLength,
		PULONG ReturnLength OPTIONAL
		);

	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	if (hNtDll == NULL) {
		return(-1);
	}

	NTSTATUS lStatus = -1;  // error by default.

	// Note that function name is not UNICODE
	PFN_NTQUERYINFORMATIONPROCESS pfnNtQIP =
		(PFN_NTQUERYINFORMATIONPROCESS)GetProcAddress(
			hNtDll, "NtQueryInformationProcess");
	if (pfnNtQIP != NULL) {
		lStatus = pfnNtQIP(hProcess, pic, pPI, cbSize, pLength);
	}

	FreeLibrary(hNtDll);
	return(lStatus);
}