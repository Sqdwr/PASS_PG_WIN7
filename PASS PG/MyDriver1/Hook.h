#pragma once
#ifndef HOOK_H
#define HOOK_H
#include <ntifs.h>
#include <ntddk.h>

#define sfExAllocate(size) ExAllocatePoolWithTag(NonPagedPool,size,'ytz')
#define sfExFree(p) {if(p != NULL){ExFreePoolWithTag(p,'ytz');p = NULL;}}

typedef VOID(*RTLCAPTURECONTEXT)(PCONTEXT);
typedef NTSTATUS(__fastcall*PSLOOKUPPROCESSBYPROCESSID)(__in HANDLE ProcessId, __deref_out PEPROCESS *Process);

extern UCHAR *PsGetProcessImageFileName(PEPROCESS Process);

extern unsigned __int64 __readcr0(void);			//读取cr0的值

extern void __writecr0(unsigned __int64 Data);		//写入cr0

extern void __debugbreak();							//断点，类似int 3

VOID PageProtectOff();

VOID PageProtectOn();

ULONG_PTR GetFuncAddress(PWSTR FuncName);			//根据函数名字获取函数地址（必须是ntoskrnl导出的）

VOID StopHook();

/*用来担当HOOK过程中的IRQL变化使用的*/
KIRQL Irql;
/*这个JmpCode很好理解就是FF 25跳转过去*/
UCHAR JmpCode[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90'};

typedef struct _HOOK_CTX
{
	ULONG64 rax;
	ULONG64 rcx;
	ULONG64 rdx;
	ULONG64 rbx;
	ULONG64 rbp;
	ULONG64 rsi;
	ULONG64 rdi;
	ULONG64 r8;
	ULONG64 r9;
	ULONG64 r10;
	ULONG64 r11;
	ULONG64 r12;
	ULONG64 r13;
	ULONG64 r14;
	ULONG64 r15;
	ULONG64 Rflags;
	ULONG64 rsp;
}HOOK_CTX, *PHOOK_CTX;

UCHAR NewCode[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90' };
/*这个OldCode就是原本顶上的十五个字节，用来恢复使用的*/
UCHAR OldCode[] = { '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90' };
/*这个数组是为了保存跳转回原函数地址上加15字节处，为什么这个是14字节，上面都是15呢，其实上面也可以是14字节，但是为了pslook上三条指令是15字节，所以用个nop占位*/
UCHAR JmpOld[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90' };
/*这个变量则是用来在HOOK的函数中调用原函数使用的*/
UCHAR *OldFunc;

#endif