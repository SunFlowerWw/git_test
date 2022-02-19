#pragma once
#include "../lib/MinHook/include/MinHook.h"

class Hk
{
public:
	Hk(LPVOID p_target, LPVOID p_detour, LPVOID pp_original = NULL);
	~Hk();
	bool op();
	bool ed();
private:
	LPVOID p_target = NULL;
	LPVOID p_detour = NULL;
	LPVOID pp_original = NULL;
	MH_STATUS err;
};
