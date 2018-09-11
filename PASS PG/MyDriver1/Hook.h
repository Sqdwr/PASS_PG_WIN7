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

extern unsigned __int64 __readcr0(void);			//��ȡcr0��ֵ

extern void __writecr0(unsigned __int64 Data);		//д��cr0

extern void __debugbreak();							//�ϵ㣬����int 3

VOID PageProtectOff();

VOID PageProtectOn();

ULONG_PTR GetFuncAddress(PWSTR FuncName);			//���ݺ������ֻ�ȡ������ַ��������ntoskrnl�����ģ�

VOID StopHook();

/*��������HOOK�����е�IRQL�仯ʹ�õ�*/
KIRQL Irql;
/*���JmpCode�ܺ�������FF 25��ת��ȥ*/
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
/*���OldCode����ԭ�����ϵ�ʮ����ֽڣ������ָ�ʹ�õ�*/
UCHAR OldCode[] = { '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90' };
/*���������Ϊ�˱�����ת��ԭ������ַ�ϼ�15�ֽڴ���Ϊʲô�����14�ֽڣ����涼��15�أ���ʵ����Ҳ������14�ֽڣ�����Ϊ��pslook������ָ����15�ֽڣ������ø�nopռλ*/
UCHAR JmpOld[] = { '\xFF', '\x25', '\x00', '\x00', '\x00', '\x00', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90', '\x90' };
/*�����������������HOOK�ĺ����е���ԭ����ʹ�õ�*/
UCHAR *OldFunc;

#endif