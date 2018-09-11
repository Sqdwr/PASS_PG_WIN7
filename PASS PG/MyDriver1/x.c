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
ULONG_PTR JmpKiRetireDpcList;					//��������ת������ĺ����ĵ�ַ
ULONG_PTR JmpRtlCaptureContext;					//��������ת������ĺ����ĵ�ַ

UCHAR *KiRetireDpcList_OldCode;
ULONG_PTR KiRetireDpcList_OldLength;

UCHAR *RtlCaptureContext_OldCode;
ULONG_PTR RtlCaptureContext_OldLength;

ULONG_PTR KiRetireDpcList_Address;				//KiRetireDpcList�ĵ�ַ,��������ǵ���DPC�ĺ���
ULONG_PTR RtlCaptureContext_Address;			//RtlCaptureContext�ĵ�ַ�����������KeBugCheckEx�е��õ���������

//һ��ƫ�������������̺߳�����ETHREAD�е�ƫ����
ULONG_PTR ThreadRoutineOffset;

VOID PageProtectOff()
{
	ULONG_PTR cr0;
	//__disable();										//�����ж�
	Irql = KeRaiseIrqlToDpcLevel();						//������DpcLevelȻ�󱣴�ԭ����IRQL
	cr0 = __readcr0();									//��ȡcr0
	cr0 &= 0xfffffffffffeffff;							//��ҳд�뱣��λ��������
	__writecr0(cr0);									//д��cr0
}

VOID PageProtectOn()
{
	ULONG_PTR cr0;
	cr0 = __readcr0();									//��ȡcr0
	cr0 |= 0x10000;										//��ԭҳ����λ
	__writecr0(cr0);									//д��cr0
	//__enable();										//��������ж�����
	KeLowerIrql(Irql);							//����IRQL�������ֵ
}

/*���ݺ������ֻ�ȡ������ַ��ֻ����ntoskrnl�����ĺ���*/
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
		KdPrint(("������ͨ��PID��ȡ��������EPROCESS\n"));
		*Process = NULL;
		return STATUS_ACCESS_DENIED;
	}

	return RetStatus;
}

VOID StartHookMyPsLookupProcessByProcessId()
{
	ULONG_PTR PsLookupAddress;

	PsLookupAddress = GetFuncAddress(L"PsLookupProcessByProcessId");

	OldFunc = (UCHAR*)sfExAllocate(sizeof(OldCode) + sizeof(JmpOld));					//�ȷ����ڴ�������������ʧ��Ҳû����Ҫ�����ˣ���Ϊ������ת�����ĺ���

	if (OldFunc == NULL)
	{
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return;
	}

	*(ULONG_PTR*)(JmpOld + 6) = PsLookupAddress + 15;									//��ת��ԭ������15���ֽڴ�

	*(ULONG_PTR*)(NewCode + 6) = (ULONG_PTR)MyPsLookupProcessByProcessId;				//��ת��ַָ�������Լ��ĺ���

	RtlCopyMemory((PVOID)OldCode, (PVOID)PsLookupAddress, sizeof(OldCode));				//����ԭ�������������15���ֽڱ�������

	PageProtectOff();

	RtlCopyMemory((PVOID)PsLookupAddress, (PVOID)NewCode, sizeof(NewCode));				//����ת������ԭ������

	PageProtectOn();

	RtlCopyMemory((PVOID)OldFunc, (PVOID)OldCode, sizeof(OldCode));						//����ԭ����ʮ����ֽڳ���

	RtlCopyMemory((PVOID)(OldFunc + sizeof(OldCode)), (PVOID)JmpOld, sizeof(JmpOld));	//������ת��ԭ������ʮ����ֽڴ���ָ�����
}

//��һ����������ҪHOOK�ĺ��������֣��ڶ����������ṩ�Ĺ��˵ĺ�����Address
VOID StartHook()
{
	LDE_DISASM LDE_Disasm = NULL;					//��ʼ�����������
	ULONG_PTR TempAddress = 0;						//��Ϊһ����ʱ������������
	ULONG_PTR AsmSize = 0;							//��ȡָ��ĳ���

	LDE_Disasm = LDE_Init();
	if (LDE_Disasm == NULL)
	{
		KdPrint(("��ʼ��LDE���������ʧ�ܣ�\n"));
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
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return;
	}
	RtlCopyMemory((PVOID)RtlCaptureContext_OldCode, (PVOID)RtlCaptureContext_Address, AsmSize);

	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)HookRtlCaptureContext;
	PageProtectOff();
	RtlCopyMemory((PVOID)RtlCaptureContext_Address, (PVOID)JmpCode, sizeof(JmpCode));				//����ת������ԭ������
	PageProtectOn();

	JmpRtlCaptureContext = (ULONG_PTR)sfExAllocate(AsmSize + sizeof(JmpCode));
	if (JmpRtlCaptureContext == 0)
	{
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return;
	}
	RtlCopyMemory((PVOID)JmpRtlCaptureContext, (PVOID)RtlCaptureContext_OldCode, AsmSize);
	RtlCopyMemory((PVOID)(JmpRtlCaptureContext + AsmSize), JmpCode, sizeof(JmpCode));
	*(ULONG_PTR*)(JmpRtlCaptureContext + AsmSize + 6) = (ULONG_PTR)(RtlCaptureContext_Address + AsmSize);
	RtlCaptureContext_OldLength = AsmSize;

	LDE_Disasm = LDE_Init();
	if (LDE_Disasm == NULL)
	{
		KdPrint(("��ʼ��LDE���������ʧ�ܣ�\n"));
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
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return;
	}
	RtlCopyMemory((PVOID)KiRetireDpcList_OldCode, (PVOID)KiRetireDpcList_Address, AsmSize);
	
	*(ULONG_PTR*)(JmpCode + 6) = (ULONG_PTR)HookKiRetireDpcList;
	PageProtectOff();
	RtlCopyMemory((PVOID)KiRetireDpcList_Address, (PVOID)JmpCode, sizeof(JmpCode));				//����ת������ԭ������
	PageProtectOn();

	JmpKiRetireDpcList = (ULONG_PTR)sfExAllocate(AsmSize + sizeof(JmpCode));
	if (JmpKiRetireDpcList == 0)
	{
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
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
		RtlCopyMemory((PVOID)TempList->HookFuncAddres, TempList->OldCode, TempList->HookNumbers);				//����ת������ԭ������
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
	//һ��ʼ����rsp+8��Ȼ��pushqdһ�Σ�Ȼ��sub 0x30,Ȼ��callһ��

	g_KeBugCheckExAddress = GetFuncAddress(L"KeBugCheckEx");

	if (Rcx == 0x109)
	{
		//PG��������
		if (Rip >= g_KeBugCheckExAddress && Rip <= g_KeBugCheckExAddress + 0x64)
		{
			//����KeBugCheckEx������
			// �Ȳ���һ��DPC
			//���IRQL�ļ��������DPC_LEVEL�ģ���˵�еĻص���ȥ�ļ�����
			//�������ͨ�ģ�������ThreadContext����
			PCHAR CurrentThread = (PCHAR)PsGetCurrentThread();
			PVOID StartRoutine = *(PVOID **)(CurrentThread + ThreadRoutineOffset);
			PVOID StackPointer = IoGetInitialStack();
			InitDpc(EmptyDpcRoutine);

			if (1) {
				//Ӧ���жϰ汾��������¶���
				PCHAR StackPage = (PCHAR)IoGetInitialStack();

				/*��ʼ���̵߳�ʱ�򣬻�����������ڲ��ֺ������ȥ�ж���һ�����MiInPageSingleKernelStack*/
				*(ULONG64 *)StackPage = (((ULONG_PTR)StackPage + 0x1000) & 0x0FFFFFFFFFFFFF000);		//stack��ʼ��MagicCode��
																										// ���û��,��win7�Ժ��ϵͳ�ϻ�50����
			}
			if (KeGetCurrentIrql() != PASSIVE_LEVEL)
			{
				//ʱ�⵹����
				BackTo1942();//�ص�call KiRetireDpcListȥ�ˣ�
			}

			//�߳�TIMER��ֱ��ִ���߳�ȥ��
			AdjustStackCallPointer(
				(ULONG_PTR)StackPointer - 0x8,					//����ԭ����-0x8���Ǹ��ݷ������Ҹ�����Ϊ����Ӧ���Ǽ�0x40
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