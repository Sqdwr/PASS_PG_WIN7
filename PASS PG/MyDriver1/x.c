#include "Hook.h"
#include "LDE.h"

extern ULONG64 GetRsp();
extern ULONG64 GetKiRetireDpcList();
extern VOID HookKiRetireDpcList();
extern VOID HookRtlCaptureContext();
extern VOID BackTo1942();
extern VOID AdjustStackCallPointer(
	IN ULONG_PTR NewStackPointer,
	IN PVOID StartAddress,
	IN PVOID Argument);

ULONG64 g_CpuContextAddress = 0;
ULONG_PTR JmpKiRetireDpcList;					//保存着跳转回最初的函数的地址
ULONG_PTR JmpRtlCaptureContext;					//保存着跳转回最初的函数的地址

UCHAR *KiRetireDpcList_OldCode;
ULONG_PTR KiRetireDpcList_OldLength;

UCHAR *RtlCaptureContext_OldCode;
ULONG_PTR RtlCaptureContext_OldLength;

ULONG_PTR KiRetireDpcList_Address;				//KiRetireDpcList的地址,这个函数是调用DPC的函数
ULONG_PTR RtlCaptureContext_Address;			//RtlCaptureContext的地址，这个函数是KeBugCheckEx中调用的蓝屏函数

//一个偏移量，代表着线程函数在ETHREAD中的偏移量
ULONG_PTR ThreadRoutineOffset;

VOID PageProtectOff()
{
	ULONG_PTR cr0;
	//__disable();										//屏蔽中断
	Irql = KeRaiseIrqlToDpcLevel();						//提升到DpcLevel然后保存原本的IRQL
	cr0 = __readcr0();									//读取cr0
	cr0 &= 0xfffffffffffeffff;							//对页写入保护位进行清零
	__writecr0(cr0);									//写入cr0
}

VOID PageProtectOn()
{
	ULONG_PTR cr0;
	cr0 = __readcr0();									//读取cr0
	cr0 |= 0x10000;										//还原页保护位
	__writecr0(cr0);									//写入cr0
	//__enable();										//允许接收中断请求
	KeLowerIrql(Irql);							//减低IRQL回最初的值
}

/*根据函数名字获取函数地址，只能是ntoskrnl导出的函数*/
ULONG_PTR GetFuncAddress(PWSTR FuncName)
{
	UNICODE_STRING uFunctionName;
	RtlInitUnicodeString(&uFunctionName, FuncName);
	return (ULONG_PTR)MmGetSystemRoutineAddress(&uFunctionName);
}

NTSTATUS __fastcall MyPsLookupProcessByProcessId(__in HANDLE ProcessId, __deref_out PEPROCESS *Process)
{
	NTSTATUS RetStatus;

	RetStatus = ((PSLOOKUPPROCESSBYPROCESSID)(OldFunc))(ProcessId, Process);
	if (NT_SUCCESS(RetStatus) && strstr((CHAR*)PsGetProcessImageFileName(*Process), "calc"))
	{
		KdPrint(("不允许通过PID获取计算器的EPROCESS\n"));
		*Process = NULL;
		return STATUS_ACCESS_DENIED;
	}

	return RetStatus;
}

VOID StartHookMyPsLookupProcessByProcessId()
{
	ULONG_PTR PsLookupAddress;

	PsLookupAddress = GetFuncAddress(L"PsLookupProcessByProcessId");

	OldFunc = (UCHAR*)sfExAllocate(sizeof(OldCode) + sizeof(JmpOld));					//先分配内存出来，如果分配失败也没必须要继续了，因为这是跳转回来的函数

	if (OldFunc == NULL)
	{
		KdPrint(("分配内存失败！\n"));
		return;
	}

	*(ULONG_PTR*)(JmpOld + 6) = PsLookupAddress + 15;									//跳转回原函数上15个字节处

	*(ULONG_PTR*)(NewCode + 6) = (ULONG_PTR)MyPsLookupProcessByProcessId;				//跳转地址指向我们自己的函数

	RtlCopyMemory((PVOID)OldCode, (PVOID)PsLookupAddress, sizeof(OldCode));				//拷贝原本函数最上面的15个字节保存起来

	PageProtectOff();

	RtlCopyMemory((PVOID)PsLookupAddress, (PVOID)NewCode, sizeof(NewCode));				//把跳转拷贝到原函数上

	PageProtectOn();

	RtlCopyMemory((PVOID)OldFunc, (PVOID)OldCode, sizeof(OldCode));						//拷贝原本的十五个字节出来

	RtlCopyMemory((PVOID)(OldFunc + sizeof(OldCode)), (PVOID)JmpOld, sizeof(JmpOld));	//拷贝跳转回原函数第十五个字节处的指令进来
}

//第一个参数是想要HOOK的函数的名字，第二个函数是提供的过滤的函数的Address
VOID StartHook()
{
	LDE_DISASM LDE_Disasm = NULL;					//初始化反汇编引擎
	ULONG_PTR TempAddress = 0;						//作为一个临时变量用来缓冲
	ULONG_PTR AsmSize = 0;							//获取指令的长度

	LDE_Disasm = LDE_Init();
	if (LDE_Disasm == NULL)
	{
		KdPrint(("初始化LDE反汇编引擎失败！\n"));
		return;
	}

	TempAddress = RtlCaptureContext_Address;
	while (TempAddress - RtlCaptureContext_Address < 14)
	{
		AsmSize = LDE_Disasm((PVOID)TempAddress, 64);
		TempAddress += AsmSize;
	}
	AsmSize = TempAddress - RtlCaptureContext_Address;
	sfExFree((PVOID)LDE_Disasm);

	RtlCaptureContext_OldCode = (UCHAR*)sfExAllocate(AsmSize);
	if (RtlCaptureContext_OldCode == NULL)
	{
		KdPrint(("分配内存失败！\n"));
		return;
	}
	RtlCopyMemory((PVOID)RtlCaptureContext_OldCode, (PVOID)RtlCaptureContext_Address, AsmSize);

	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)HookRtlCaptureContext;
	PageProtectOff();
	RtlCopyMemory((PVOID)RtlCaptureContext_Address, (PVOID)JmpCode, sizeof(JmpCode));				//把跳转拷贝到原函数上
	PageProtectOn();

	JmpRtlCaptureContext = (ULONG_PTR)sfExAllocate(AsmSize + sizeof(JmpCode));
	if (JmpRtlCaptureContext == 0)
	{
		KdPrint(("分配内存失败！\n"));
		return;
	}
	RtlCopyMemory((PVOID)JmpRtlCaptureContext, (PVOID)RtlCaptureContext_OldCode, AsmSize);
	RtlCopyMemory((PVOID)(JmpRtlCaptureContext + AsmSize), JmpCode, sizeof(JmpCode));
	*(ULONG_PTR*)(JmpRtlCaptureContext + AsmSize + 6) = (ULONG_PTR)(RtlCaptureContext_Address + AsmSize);
	RtlCaptureContext_OldLength = AsmSize;

	LDE_Disasm = LDE_Init();
	if (LDE_Disasm == NULL)
	{
		KdPrint(("初始化LDE反汇编引擎失败！\n"));
		return;
	}

	TempAddress = KiRetireDpcList_Address;
	while (TempAddress - KiRetireDpcList_Address < 14)
	{
		AsmSize = LDE_Disasm((PVOID)TempAddress, 64);
		TempAddress += AsmSize;
	}
	AsmSize = TempAddress - KiRetireDpcList_Address;
	sfExFree((PVOID)LDE_Disasm);

	KiRetireDpcList_OldCode = (UCHAR*)sfExAllocate(AsmSize);
	if (KiRetireDpcList_OldCode == NULL)
	{
		KdPrint(("分配内存失败！\n"));
		return;
	}
	RtlCopyMemory((PVOID)KiRetireDpcList_OldCode, (PVOID)KiRetireDpcList_Address, AsmSize);
	
	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)HookKiRetireDpcList;
	PageProtectOff();
	RtlCopyMemory((PVOID)KiRetireDpcList_Address, (PVOID)JmpCode, sizeof(JmpCode));				//把跳转拷贝到原函数上
	PageProtectOn();

	JmpKiRetireDpcList = (ULONG_PTR)sfExAllocate(AsmSize + sizeof(JmpCode));
	if (JmpKiRetireDpcList == 0)
	{
		KdPrint(("分配内存失败！\n"));
		return;
	}
	RtlCopyMemory((PVOID)JmpKiRetireDpcList, (PVOID)KiRetireDpcList_OldCode, AsmSize);
	RtlCopyMemory((PVOID)(JmpKiRetireDpcList + AsmSize), JmpCode, sizeof(JmpCode));
	*(ULONG_PTR*)(JmpKiRetireDpcList + AsmSize + 6) = (ULONG_PTR)(KiRetireDpcList_Address + AsmSize);
	KiRetireDpcList_OldLength = AsmSize;
}

VOID StopHook()
{
	/*PHOOKITEM TempList;

	TempList = (PHOOKITEM)ExInterlockedRemoveHeadList(&HookListHead, &HookSpinLock);
	while (TempList != NULL)
	{
		PageProtectOff();
		RtlCopyMemory((PVOID)TempList->HookFuncAddres, TempList->OldCode, TempList->HookNumbers);				//把跳转拷贝到原函数上
		PageProtectOn();
		sfExFree(TempList->OldCode);
		sfExFree(TempList->OldFunc);
		sfExFree(TempList);
		TempList = (PHOOKITEM)ExInterlockedRemoveHeadList(&HookListHead, &HookSpinLock);
	}*/

}

VOID MyDpcRoutine(
	__in struct _KDPC *Dpc,
	__in_opt PVOID DeferredContext,
	__in_opt PVOID SystemArgument1,
	__in_opt PVOID SystemArgument2
)
{
	ULONG_PTR EndAddress;
	UCHAR *i;

	KiRetireDpcList_Address = GetKiRetireDpcList();

	EndAddress = KiRetireDpcList_Address;
	while (KiRetireDpcList_Address - EndAddress < 0x200)
	{
		i = (UCHAR*)EndAddress;
		if (*i == 0xff && *(i + 1) == 0xf3 &&			//push rbx
			*(i + 2) == 0x55 &&							//push rbp
			*(i + 3) == 0x56 &&							//push rsi
			*(i + 4) == 0x57)							//push rdi
			break;
		--EndAddress;
	}

	KiRetireDpcList_Address = EndAddress;
	ExFreePoolWithTag(Dpc, 'ytz');
}

VOID
EmptyDpcRoutine(
	IN struct _KDPC *Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
)
{
	return;
}

VOID DisablePatchGuardSystemThreadRoutine(IN PVOID Context)
{
	UCHAR *CurrentThread = (UCHAR*)PsGetCurrentThread();
	ULONG_PTR StackPoint;

	StackPoint = (ULONG_PTR)IoGetInitialStack();
	
	while (*(ULONG_PTR*)CurrentThread != (ULONG_PTR)DisablePatchGuardSystemThreadRoutine)
		++CurrentThread;

	ThreadRoutineOffset = (ULONG_PTR)CurrentThread - (ULONG_PTR)PsGetCurrentThread();
	
	StartHook();

	StartHookMyPsLookupProcessByProcessId();

	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID InitDpc(PKDEFERRED_ROUTINE DpcRoutine)
{
	PKDPC dpc = (PKDPC)sfExAllocate(sizeof(KDPC));
	RtlZeroMemory(dpc, sizeof(KDPC));
	KeInitializeDpc(dpc, DpcRoutine, NULL);
	KeInsertQueueDpc(dpc, NULL, NULL);
}

VOID CreateSystemThread(PKSTART_ROUTINE ThreadRoutine)
{
	OBJECT_ATTRIBUTES Attributes;
	NTSTATUS Status;
	HANDLE ThreadHandle;

	InitializeObjectAttributes(
		&Attributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	Status = PsCreateSystemThread(
		&ThreadHandle,
		THREAD_ALL_ACCESS,
		&Attributes,
		NULL,
		NULL,
		ThreadRoutine,
		NULL);

	if (NT_SUCCESS(Status))
		ZwClose(ThreadHandle);
}

VOID OnRtlCaptureContext(PHOOK_CTX hookCtx)
{
	ULONG64 Rcx;
	PCONTEXT pCtx = (PCONTEXT)(hookCtx->rcx);
	ULONG64 Rip = *(ULONG64 *)(hookCtx->rsp);
	ULONG_PTR g_KeBugCheckExAddress;

	((RTLCAPTURECONTEXT)JmpRtlCaptureContext)(pCtx);

	pCtx->Rsp = hookCtx->rsp + 0x08;
	pCtx->Rip = Rip;
	pCtx->Rax = hookCtx->rax;
	pCtx->Rbx = hookCtx->rbx;
	pCtx->Rcx = hookCtx->rcx;
	pCtx->Rdx = hookCtx->rdx;
	pCtx->Rsi = hookCtx->rsi;
	pCtx->Rdi = hookCtx->rdi;
	pCtx->Rbp = hookCtx->rbp;

	pCtx->R8 = hookCtx->r8;
	pCtx->R9 = hookCtx->r9;
	pCtx->R10 = hookCtx->r10;
	pCtx->R11 = hookCtx->r11;
	pCtx->R12 = hookCtx->r12;
	pCtx->R13 = hookCtx->r13;
	pCtx->R14 = hookCtx->r14;
	pCtx->R15 = hookCtx->r15;

	Rcx = *(ULONG64 *)(hookCtx->rsp + 0x48);
	//一开始就是rsp+8，然后pushqd一次，然后sub 0x30,然后call一次

	g_KeBugCheckExAddress = GetFuncAddress(L"KeBugCheckEx");

	if (Rcx == 0x109)
	{
		//PG的蓝屏！
		if (Rip >= g_KeBugCheckExAddress && Rip <= g_KeBugCheckExAddress + 0x64)
		{
			//来自KeBugCheckEx的蓝屏
			// 先插入一个DPC
			//检测IRQL的级别，如果是DPC_LEVEL的，则传说中的回到过去的技术。
			//如果是普通的，则跳入ThreadContext即可
			PCHAR CurrentThread = (PCHAR)PsGetCurrentThread();
			PVOID StartRoutine = *(PVOID **)(CurrentThread + ThreadRoutineOffset);
			PVOID StackPointer = IoGetInitialStack();
			InitDpc(EmptyDpcRoutine);

			if (1) {
				//应该判断版本再做这个事儿！
				PCHAR StackPage = (PCHAR)IoGetInitialStack();

				/*初始化线程的时候，会设置这个。在部分函数里会去判断这一项，例如MiInPageSingleKernelStack*/
				*(ULONG64 *)StackPage = (((ULONG_PTR)StackPage + 0x1000) & 0x0FFFFFFFFFFFFF000);		//stack起始的MagicCode，
																										// 如果没有,在win7以后的系统上会50蓝屏
			}
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
			{
				//时光倒流！
				BackTo1942();//回到call KiRetireDpcList去了！
			}

			//线程TIMER的直接执行线程去！
			AdjustStackCallPointer(
				(ULONG_PTR)StackPointer - 0x8,					//这里原文是-0x8但是根据分析，我个人认为这里应该是减0x40
				StartRoutine,
				NULL);
		}
	}
	return;
}

VOID Init()
{
	InitDpc(MyDpcRoutine);
	RtlCaptureContext_Address = GetFuncAddress(L"RtlCaptureContext");
	KdPrint(("RtlCaptureContext : %llx\n", RtlCaptureContext_Address));
	KdPrint(("KiRetireDpcList : %llx\n", KiRetireDpcList_Address));

	g_CpuContextAddress = (ULONG_PTR)sfExAllocate(0x200 * KeNumberProcessors + 0x1000);

	CreateSystemThread(DisablePatchGuardSystemThreadRoutine);

	//StartHook(L"NtCreateFile", (ULONG_PTR)MyNtCreateFile);
	//StartHook(L"PsLookupProcessByProcessId",(ULONG_PTR)MyPsLookupProcessByProcessId);
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	StopHook();
	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	
	Init();
	
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}