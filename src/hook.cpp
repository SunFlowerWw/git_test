#include <Windows.h>
#include "../inc/hook.h"

#pragma comment(lib, "../lib/MinHook/lib/libMinHook-x64-v141-mt.lib")

Hk::Hk(LPVOID p_target, LPVOID p_detour, LPVOID pp_original)
	:p_target(p_target), p_detour(p_detour), pp_original(pp_original)
{
	MH_Initialize();
	MH_CreateHook(p_target, p_detour, reinterpret_cast<LPVOID*>(pp_original));
}

Hk::~Hk()
{
	MH_Uninitialize();
}

bool Hk::op()
{
	MH_EnableHook(p_target);
	return false;
}

bool Hk::ed()
{
	MH_DisableHook(p_target);
	return false;
}