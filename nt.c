#include "nt.h"
#include <ntstrsafe.h>

NT_INFORMATIONS NtInformations;
NT_STRUCT_INFORMATIONS NtStructInformations;

VOID NtExInitializeSymbolsTable(PIO_DISPATCH_HEADER pHead)
{
	PSYMBOL_MAP_HEAD_INFO InputMap;

#ifdef _DBG
	UNICODE_STRING TestModuleName;
	PSYMBOL_MAP_ITEM_INFO pItem;
	PSYSTEM_PROCESS_INFORMATION ProcessInfo;
	ULONG ProcessInfoLength;
	PVOID ProcessObjectType;
	POBJECT_HEADER_NAME_INFO pNameInfo;
#endif

	// Initialized
	if (NtInformations.NtSymbolMapHead != NULL)
	{
		return;
	}
	
	if (pHead == NULL || pHead->Body.InBuffLen == 0)
	{
		return;
	}
	// Allocate new map
	NtInformations.NtSymbolMapHead = (PSYMBOL_MAP_HEAD_INFO)ExAllocatePool(NonPagedPool, pHead->Body.InBuffLen);
	if (NtInformations.NtSymbolMapHead == NULL)
	{
		DbgPrint("Allocate symbols map faild\n");
		return;
	}

	// get input map 
	InputMap = (PSYMBOL_MAP_HEAD_INFO)(pHead);
	
#ifdef _DBG
	KdPrint(("Load symbols success Imagebase = %p NumberOfSymbol = %x \n",
				InputMap->ImageBase, InputMap->NumberOfItem));
#endif

	// Check header is valid
	if (InputMap->DispatchHead.SizeOfHeader != sizeof(IO_DISPATCH_HEADER) || 
		InputMap->SizeOfHeader != sizeof(SYMBOL_MAP_HEAD_INFO))
	{
		DbgPrint("Input symbol map invalid\n");
		return;
	}

	if (!MmIsAddressValid((PCHAR)InputMap + InputMap->MemoryUsege))
	{
		DbgPrint("Input symbol map too large in size \n");
		return;
	}

	// Copy map to new map
	RtlCopyMemory((PVOID)NtInformations.NtSymbolMapHead, (PVOID)InputMap,InputMap->MemoryUsege);

	// complete io dispatch
	pHead->Body.OutBuff = NULL;
	pHead->Body.OutBuffLen = 0;
	pHead->Body.Status = STATUS_SUCCESS;

	// Get kernel base
	// If kernel reloaded from hack? this funciton return values is new kernel base
	// If use this kernel base init symbols , and this symbols only pointer to the new kernel variable
	// But don't worry , reload kernel must fix global variable , so symbols still pointer to the old kernel variables

	NtInformations.KernelBase = NtExGetKernelBaseFromUnDocumentFunction();
	if(NtInformations.KernelBase == NULL)
	{
		DbgPrint("Get kernel base from ZwQuerySystemInformation faild \n");
		return ;
	}

	KdBreakPoint();
	// Init some symbols and check kernel is reloaded
	NtExInitializeUnDocumentInformation();

	// Init some struct offset information
	NtExInitializeStructInformations();

	// set initialize success flag
	// if initialize faild this frame only use prefix pointer to the function or variable
	NtInformations.Initialized = TRUE;

	//
	// Test
	//
#ifdef _DBG
	if(NtInformations.pKdDebuggerDataBlock != NULL)
	{
		KdPrint(("[Log] Symbols load success \n \
			  KernelBase = %p\n \
			  PsLoadedModuleList = %p\n	\
			  PsActiveProcessHead = %p\n \
			  PspCidTable = %p\n \
			  ObpRootDirectoryObject = %p\n \
			  ObpTypeObjectType = %p\n 	\
			  ObTypeIndexTable = %p",	\
			  (NtInformations.pKdDebuggerDataBlock)->KernBase,	\
			  (NtInformations.pKdDebuggerDataBlock)->PsLoadedModuleList,	\
			  (NtInformations.pKdDebuggerDataBlock)->PsActiveProcessHead, \
			  (NtInformations.pKdDebuggerDataBlock)->PspCidTable,	\
			  (NtInformations.pKdDebuggerDataBlock)->ObpRootDirectoryObject,	\
			  (NtInformations.pKdDebuggerDataBlock)->ObpTypeObjectType	,
			  NtInformations.ObTypeIndexTable \
			));
	}
	if (NtInformations.pPsLoadedModuleResource != NULL)
	{
		RtlInitUnicodeString(&TestModuleName, L"win32k.sys");

		KdPrint(("[Log] Safe Get Kernel Module Base \n	 \
			win32k.sys : %p\n",	\
			NtExGetModuleBaseFromModuleList(&TestModuleName)	\
			));
	}
	
	pItem = NtExGetStructChildInfo("_EPROCESS","ActiveProcessLinks");
	if(pItem != NULL)
	{
		KdPrint(("[Log] Get ActiveProcessLinks from _EPROCESS by symbols offset: %x\n", \
		pItem->Offset	\
		));
	}

	if (NtExSnapProcessInformation(NULL, 0, &ProcessInfoLength) == STATUS_INFO_LENGTH_MISMATCH)
	{
		ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)ExAllocatePool(NonPagedPool, ProcessInfoLength);
		if (ProcessInfo != NULL)
		{
			if (NtExSnapProcessInformation(ProcessInfo, ProcessInfoLength, &ProcessInfoLength) == STATUS_SUCCESS)
			{
				KdPrint(("[Log] Snap Process information from ActiveProcessLinks Success\n"));
			}
			ExFreePool((PVOID)ProcessInfo);
		}
	}

	// Test Get Object Type
	ProcessObjectType = NtExGetObjectType(PsGetCurrentProcess());
	pNameInfo = NtExGetObjectNameInfo(ProcessObjectType);
	KdPrint(("[Log] ProcessObjectType : %p \n",ProcessObjectType));
	KdPrint(("[Log] Object Name : %wZ \n", &pNameInfo->Name));

#endif	
}

BOOLEAN NtExInitialization()
{
	RtlZeroMemory((PVOID)&NtInformations, sizeof(NT_INFORMATIONS));
	return TRUE;
}

BOOLEAN NtExUnInitialization()
{
	if (NtInformations.NtSymbolMapHead != NULL)
	{
		ExFreePool((PVOID)NtInformations.NtSymbolMapHead);
		NtInformations.NtSymbolMapHead = NULL;
	}
	return TRUE;
}

BOOLEAN NtExInitializeUnDocumentInformation()
{
	DWORD64 Offset;
	PSYMBOL_MAP_HEAD_INFO pHead;

	if(NtInformations.Initialized == TRUE)
	{
		return TRUE;
	}
	if(NtInformations.NtSymbolMapHead == NULL || NtInformations.KernelBase == NULL)
	{
		return FALSE;
	}

	// Init
	pHead = NtInformations.NtSymbolMapHead;
	Offset = (DWORD64)(pHead->ImageBase) -  (DWORD64)(NtInformations.KernelBase);

	// KdDebuggerDataBlock
	NtInformations.pKdDebuggerDataBlock = (PKDDEBUGGER_DATA64)NtExGetSymbolsAddress("KdDebuggerDataBlock",Offset);

	// Fix kernel base
	if((NtInformations.pKdDebuggerDataBlock)->KernBase != (ULONG64)NtInformations.KernelBase)
	{
		NtInformations.KernelBase = NtInformations.pKdDebuggerDataBlock;
		// Fix offset
		Offset = (DWORD64)(pHead->ImageBase) -  (DWORD64)(NtInformations.KernelBase);
	}	

	// PsLoadedModuleResource
	NtInformations.pPsLoadedModuleResource = (PERESOURCE)NtExGetSymbolsAddress("PsLoadedModuleResource",Offset);

	// PspActiveProcessMutex
	NtInformations.pPspActiveProcessMutex = (PKGUARDED_MUTEX)NtExGetSymbolsAddress("PspActiveProcessMutex",Offset);

	// PspActiveProcessLock
	NtInformations.pPspActiveProcessLock = (PEX_PUSH_LOCK)NtExGetSymbolsAddress("PspActiveProcessLock",Offset);

	// ObTypeIndexTable
	NtInformations.ObTypeIndexTable = (PVOID)NtExGetSymbolsAddress("ObTypeIndexTable",Offset);

	// ObHeaderCookie
	NtInformations.pObHeaderCookie = (PINT8)NtExGetSymbolsAddress("ObHeaderCookie",Offset);

	// ObpInfoMaskToOffset
	NtInformations.pObpInfoMaskToOffset = (PINT8)NtExGetSymbolsAddress("ObpInfoMaskToOffset",Offset);	

	// PspCreateProcess
	NtInformations.PspCreateProcess = (PSPCREATEPROCESS)NtExGetSymbolsAddress("PspCreateProcess",Offset);

	// NtCreateProcess
	NtInformations.NtCreateProcess = (NTCREATEPROCESS)NtExGetSymbolsAddress("NtCreateProcess",Offset);

	// NtCreateProcessEx
	NtInformations.NtCreateProcessEx = (NTCREATEPROCESSEX)NtExGetSymbolsAddress("NtCreateProcessEx",Offset);

	// NtCreateUserProcess
	NtInformations.NtCreateUserProcess = (NTCREATEUSERPROCESS)NtExGetSymbolsAddress("NtCreateUserProcess",Offset);
	
	// NtCreateFile
	NtInformations.NtCreateFile = (NTCREATEFILE)NtExGetSymbolsAddress("NtCreateFile",Offset);
	
	// NtShutdownSystem
	NtInformations.NtShutdownSystem = (NTSHUTDOWNSYSTEM)NtExGetSymbolsAddress("NtShutdownSystem",Offset);
	
	return TRUE;
}

BOOLEAN NtExInitializeStructInformations()
{
	PSYMBOL_MAP_ITEM_INFO pItem;

	RtlFillBytes((PVOID)&NtStructInformations,sizeof(NT_STRUCT_INFORMATIONS),0xff);

	if(NtInformations.Initialized == TRUE)
	{
		return TRUE;
	}
	if(NtInformations.NtSymbolMapHead == NULL)
	{
		return FALSE;
	}

	pItem = NtExGetSymbolsStructHead("_OBJECT_HEADER");
	if (pItem != NULL)
	{
		NtStructInformations.Struct_Header_OBJECT_HEADER = pItem;
		NtStructInformations.Offset_InfoMask_OBJECT_HEADER = (INT16)((NtExGetStructChildInfoByHead(pItem, "InfoMask"))->Offset);
		NtStructInformations.Offset_TypeIndex_OBJECT_HEADER = (INT16)((NtExGetStructChildInfoByHead(pItem, "TypeIndex"))->Offset);	
	}

	pItem = NtExGetSymbolsStructHead("_EPROCESS");
	if (pItem != NULL)
	{
		NtStructInformations.Struct_Header_EPROCESS = pItem;
		NtStructInformations.Offset_ActiveProcessLinks_EPROCESS = (INT16)((NtExGetStructChildInfoByHead(pItem, "ActiveProcessLinks"))->Offset);
		NtStructInformations.Offset_UniqueProcessId_EPROCESS = (INT16)((NtExGetStructChildInfoByHead(pItem, "UniqueProcessId"))->Offset);	
		NtStructInformations.Offset_SeAuditProcessCreationInfo_EPROCESS = (INT16)((NtExGetStructChildInfoByHead(pItem, "SeAuditProcessCreationInfo"))->Offset);	
		NtStructInformations.Offset_ImageFileName_EPROCESS = (INT16)((NtExGetStructChildInfoByHead(pItem, "ImageFileName"))->Offset);	
		NtStructInformations.Offset_VirtualSize_EPROCESS = (INT16)((NtExGetStructChildInfoByHead(pItem, "VirtualSize"))->Offset);
	}

	return FALSE;
}

PVOID NtExGetSymbolsAddress(const PCHAR pName,DWORD64 fixOffset)
{
	ANSI_STRING SymbolName;
	PSYMBOL_MAP_ITEM_INFO pItem;

	RtlInitAnsiString(&SymbolName,pName);
	if(SymMapLookupSymbol(&NtInformations.NtSymbolMapHead,&SymbolName,&pItem))
	{
		if(pItem == NULL)
		{
			return NULL;
		} 
		else
		{
			return 	(PVOID)(pItem->Address - fixOffset);
		}
	}
	else
	{
		return NULL;	
	}
	return NULL;
}

PSYMBOL_MAP_ITEM_INFO NtExGetSymbolsStructHead(const PCHAR pName)
{
	ANSI_STRING SymbolName;
	PSYMBOL_MAP_ITEM_INFO pItem;

	RtlInitAnsiString(&SymbolName,pName);
	if(SymMapLookupSymbol(&NtInformations.NtSymbolMapHead,&SymbolName,&pItem))
	{
		if(pItem == NULL)
		{
			return NULL;
		} 
		else
		{
			return 	pItem;
		}
	}
	else
	{
		return NULL;	
	}
	return NULL;
}

PSYMBOL_MAP_ITEM_INFO NtExGetStructChildInfo(const PCHAR pStructName, const PCHAR pChildName)
{
	PSYMBOL_MAP_ITEM_INFO pStructHead;

	if(pStructName == NULL || pChildName == NULL)
	{
		return NULL;
	}
	// Get struct header
	pStructHead = NtExGetSymbolsStructHead(pStructName);
	// Get child header
	return NtExGetStructChildInfoByHead(pStructHead,pChildName);
}

PSYMBOL_MAP_ITEM_INFO NtExGetStructChildInfoByHead(PSYMBOL_MAP_ITEM_INFO pStructHead,const PCHAR pChildName)
{
	DWORD32 Index;
	NTSTATUS status;
	SIZE_T MaxLength;
	SIZE_T ActualLength;
	DWORD64 StructStart, StructEnd;
	ANSI_STRING SymbolName;
	ANSI_STRING SymbolName2;
	PSYMBOL_MAP_ITEM_INFO pChildInfo;

	RtlInitAnsiString(&SymbolName, pChildName);
	if (pStructHead != NULL)
	{
		if (pStructHead->ChildCount <= 512)
		{
			StructStart = (DWORD64)pStructHead;
			StructEnd = StructStart + pStructHead->SizeOfType;

#ifdef _KERNEL_MODE
			if (!MmIsAddressValid((PVOID)StructStart) || !MmIsAddressValid((PVOID)StructEnd))
			{
				return NULL;
			}
#endif
			// Enum child
			pChildInfo = (PSYMBOL_MAP_ITEM_INFO)((DWORD64)pStructHead + pStructHead->SizeOfItem);
			for (Index = 0; Index < pStructHead->ChildCount; Index++)
			{
				// safe get child name
				SymbolName2.Buffer = (PCHAR)((DWORD64)pChildInfo + pChildInfo->NameOffset);
				MaxLength = StructEnd - (DWORD64)(SymbolName2.Buffer);

#ifdef _KERNEL_MODE
				status = RtlStringCbLengthA(SymbolName2.Buffer, MaxLength, &ActualLength);

				if (status == STATUS_INVALID_PARAMETER)
				{
					// Invalid symbol map
					return FALSE;
				}
				// Invalid symbol name
				if (ActualLength != pChildInfo->NameLen)
				{
					return FALSE;
				}
				SymbolName2.Length = (USHORT)ActualLength;
				SymbolName2.MaximumLength = (USHORT)ActualLength;
#else
				SymbolName2.Length = (USHORT)pChildInfo->NameLen;
				SymbolName2.MaximumLength = (USHORT)pChildInfo->NameLen;
#endif

#ifdef _KERNEL_MODE
				if (RtlCompareString(&SymbolName, &SymbolName2, FALSE) == 0)
				{
					return pChildInfo;
				}
#else
				// un safe
				if (memcmp((PVOID)Name, (PVOID)((PCHAR)pItem + pItem->NameOffset), pItem->NameLen) == 0)
				{
					return pChildInfo
				}
#endif
				pChildInfo = (PSYMBOL_MAP_ITEM_INFO)((DWORD64)pChildInfo + pChildInfo->SizeOfItem);
			}
		}
	}
	return NULL;
}

PVOID NtExGetFirstKpcr()
{
	PVOID p = NULL;
	GROUP_AFFINITY NewAFFINITY;
	GROUP_AFFINITY OldAFFINITY;
	NewAFFINITY.Mask = 1;
	NewAFFINITY.Group = 0;
	KeSetSystemGroupAffinityThread(&NewAFFINITY,&OldAFFINITY);
#ifdef _WIN64
	p = (PVOID)(__readgsqword(0x20) - 0x180);
#endif
	KeRevertToUserGroupAffinityThread(&OldAFFINITY);
	return p;
}

PVOID NtExGetModuleBaseFromDriverObject(PDRIVER_OBJECT pDriverObject,PUNICODE_STRING pModuleName)
{
	if (pDriverObject != NULL && pModuleName != NULL)
	{
		PLIST_ENTRY ModuleList = (PLIST_ENTRY)pDriverObject->DriverSection;
		PLIST_ENTRY pNextEntry = ModuleList;
		PVOID	DllBase = 0;
		PUNICODE_STRING BaseDllName = NULL;

		if (ModuleList != NULL)
		{
			do
			{
#ifdef _WIN64
				BaseDllName = (PUNICODE_STRING)((PUCHAR)pNextEntry + 0x58);
				DllBase = (PVOID)*(PDWORD64)((PUCHAR)pNextEntry + 0x30);
#else
				BaseDllName = (PUNICODE_STRING)((PUCHAR)pNextEntry + 0x2c);
				DllBase = (PVOID)*(PDWORD32)((PUCHAR)ModuleList + 0x18);
#endif
				if (RtlCompareUnicodeString(BaseDllName, pModuleName, FALSE) == 0)
				{
					return DllBase;
				}
				pNextEntry = pNextEntry->Blink;
			} while (pNextEntry != NULL && pNextEntry != ModuleList);
			return NULL;
		}
		return NULL;
	}
	return NULL;
}

PVOID NtExGetKernelBaseFromDriverObject(PDRIVER_OBJECT pDriverObject)
{
	PVOID BaseFromModuleList = NULL;
	// From Module List
	UNICODE_STRING KernelName[4];
	RtlInitUnicodeString(&KernelName[0], L"ntoskrnl.exe");
	RtlInitUnicodeString(&KernelName[1], L"ntkrnlpa.exe");
	RtlInitUnicodeString(&KernelName[2], L"ntkrnlmp.exe");
	RtlInitUnicodeString(&KernelName[3], L"ntkrpamp.exe");

	BaseFromModuleList = NtExGetModuleBaseFromDriverObject(pDriverObject,&KernelName[0]);
	if (BaseFromModuleList == NULL)
	{
		BaseFromModuleList = NtExGetModuleBaseFromDriverObject(pDriverObject,&KernelName[1]);
		if (BaseFromModuleList == NULL)
		{
			BaseFromModuleList = NtExGetModuleBaseFromDriverObject(pDriverObject,&KernelName[2]);
			if (BaseFromModuleList == NULL)
			{
				BaseFromModuleList = NtExGetModuleBaseFromDriverObject(pDriverObject,&KernelName[3]);
			}
		}
	}
	return BaseFromModuleList;
}

PVOID NtExGetKernelBaseFromUnDocumentFunction()
{
	NTSTATUS status;
	PVOID Base;
	ULONG NeedLen = 0;
	PSYSTEM_MODULE_INFORMATION ModuleInfo = NULL;

	status = ZwQuerySystemInformation(11, NULL, 0, &NeedLen);

	ModuleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, NeedLen);
	if (ModuleInfo == NULL)
	{
		return NULL;
	}
	status = ZwQuerySystemInformation(11, ModuleInfo, NeedLen, &NeedLen);
	if (NT_SUCCESS(status))
	{
		Base = ModuleInfo->Module[0].Base;
		ExFreePool(ModuleInfo);
		return Base;
	}
	return NULL;
}

PVOID NtExGetModuleBaseFromModuleList(PUNICODE_STRING pName)
{
	PVOID DllBase;
	PLIST_ENTRY Next;
	PUNICODE_STRING BaseDllName;
	PLIST_ENTRY LoadOrderListHead;

	if (pName == NULL ||	\
		NtInformations.Initialized == FALSE ||	\
		NtInformations.pPsLoadedModuleResource == NULL ||	\
		NtInformations.pKdDebuggerDataBlock->PsLoadedModuleList == 0)
	{
		return NULL;
	}
	LoadOrderListHead = (PLIST_ENTRY)(NtInformations.pKdDebuggerDataBlock->PsLoadedModuleList);
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(NtInformations.pPsLoadedModuleResource, TRUE);
	Next = LoadOrderListHead->Flink;
	while (Next != LoadOrderListHead)
	{

#ifdef _WIN64
		BaseDllName = (PUNICODE_STRING)((PUCHAR)Next + 0x58);
		DllBase = (PVOID) * (PDWORD64)((PUCHAR)Next + 0x30);
#else
		BaseDllName = (PUNICODE_STRING)((PUCHAR)Next + 0x2c);
		DllBase = (PVOID) * (PDWORD32)((PUCHAR)Next + 0x18);
#endif

		if (RtlCompareUnicodeString(BaseDllName, pName, FALSE) == 0)
		{
			break;
		}
		Next = Next->Flink;
	}
	ExReleaseResourceLite(NtInformations.pPsLoadedModuleResource);
	KeLeaveCriticalRegion();
	return DllBase;
}

NTSTATUS NtExSnapProcessInformation(PVOID ProcessInfo,ULONG InfoLength,PULONG OutLength)
{
	NTSTATUS status;
	ULONG Index;
	ULONG Total = 0;
	PEPROCESS pEprocess;
	PLIST_ENTRY Next;
	PLIST_ENTRY ActiveProcessList;
	PSYSTEM_PROCESS_INFORMATION InforBuffer;
	DWORD64 ListOffset;
	DWORD64 ProcessIdOffset;
	DWORD64 ImageFileNameOffset;
	DWORD64 ImageFileNameOffset2;
	DWORD64 VirtualSizeOffset;
	SIZE_T NameLength;
	PUNICODE_STRING pImageFileName;
	PCHAR pImageFileName2;

	if (OutLength == NULL)
	{
		return STATUS_INVALID_PARAMETER_3;
	}
	if (NtInformations.Initialized == FALSE ||
		NtInformations.pKdDebuggerDataBlock->PsActiveProcessHead == 0)
	{
		return STATUS_UNSUCCESSFUL;
	}
	InforBuffer = (PSYSTEM_PROCESS_INFORMATION)ProcessInfo;

	//
	// Init offset
	//

	if (NtStructInformations.Offset_ActiveProcessLinks_EPROCESS == 0xffff ||
		NtStructInformations.Offset_UniqueProcessId_EPROCESS == 0xffff ||
		NtStructInformations.Offset_SeAuditProcessCreationInfo_EPROCESS == 0xffff ||
		NtStructInformations.Offset_ImageFileName_EPROCESS == 0xffff ||
		NtStructInformations.Offset_VirtualSize_EPROCESS == 0xffff)
	{
		return STATUS_UNSUCCESSFUL;
	}

	ListOffset = NtStructInformations.Offset_ActiveProcessLinks_EPROCESS;
	ProcessIdOffset = NtStructInformations.Offset_UniqueProcessId_EPROCESS;
	ImageFileNameOffset = NtStructInformations.Offset_SeAuditProcessCreationInfo_EPROCESS;
	ImageFileNameOffset2 = NtStructInformations.Offset_ImageFileName_EPROCESS;
	VirtualSizeOffset = NtStructInformations.Offset_VirtualSize_EPROCESS;

	// Lock Process List
	KeEnterGuardedRegion();
	
	if(NtInformations.pPspActiveProcessMutex)
		KeAcquireGuardedMutexUnsafe(NtInformations.pPspActiveProcessMutex); //WIN XP or 2K
	else if(NtInformations.pPspActiveProcessLock)
		ExfAcquirePushLockShared(NtInformations.pPspActiveProcessLock); // WIN 7 ~ 10

	ActiveProcessList = (PLIST_ENTRY)(NtInformations.pKdDebuggerDataBlock->PsActiveProcessHead);

	// trace list
	if (InforBuffer != NULL)
	{
		RtlZeroMemory((PVOID)ProcessInfo,InfoLength);
		Next = ActiveProcessList->Flink;
		while (Next != ActiveProcessList)
		{
			Total += sizeof(SYSTEM_PROCESS_INFORMATION);
			if (InfoLength < Total)
			{
				break;
			}
			// Get process informaiton
			pEprocess = (PEPROCESS)((DWORD64)Next - ListOffset);
			InforBuffer->pEprocess = pEprocess;
			InforBuffer->UniqueProcessId = *(PHANDLE)((DWORD64)pEprocess + ProcessIdOffset);
			InforBuffer->VirtualSize = *(PSIZE_T)((DWORD64)pEprocess + VirtualSizeOffset);

			// Copy Image file name
			pImageFileName = (PUNICODE_STRING)(*(PDWORD64)((DWORD64)pEprocess + ImageFileNameOffset));

			if (pImageFileName != NULL && pImageFileName->Buffer != NULL)
			{
				if (InfoLength < Total || ((DWORD64)InforBuffer >= (DWORD64)ProcessInfo + InfoLength))
				{
					status = STATUS_BUFFER_TOO_SMALL;
					break;
				}
				//Copy
				RtlCopyMemory((PVOID)((DWORD64)InforBuffer + sizeof(SYSTEM_PROCESS_INFORMATION)),
							  pImageFileName->Buffer,
							  pImageFileName->MaximumLength);

				InforBuffer->ImageName.Buffer = (PVOID)((DWORD64)InforBuffer + sizeof(SYSTEM_PROCESS_INFORMATION));
				InforBuffer->ImageName.Length = pImageFileName->Length;
				InforBuffer->ImageName.MaximumLength = pImageFileName->Length + sizeof(WCHAR);
			}
			else
			{
				pImageFileName2 = (PCHAR)((DWORD64)pEprocess + ImageFileNameOffset2);
				if(NT_SUCCESS(RtlStringCbLengthA(pImageFileName2,16,&NameLength)))
				{
					InforBuffer->ImageName.Length = (USHORT)NameLength * sizeof(WCHAR);
					InforBuffer->ImageName.MaximumLength = (USHORT)NameLength * sizeof(WCHAR) + sizeof(WCHAR);
				}
				else
				{
					InforBuffer->ImageName.Length =  16*sizeof(WCHAR);
					InforBuffer->ImageName.MaximumLength = 16*sizeof(WCHAR);
				}
				InforBuffer->ImageName.Buffer = (PVOID)((DWORD64)InforBuffer + sizeof(SYSTEM_PROCESS_INFORMATION));
				// CHAR TO WCHAR 
				for(Index = 0;Index < 15;Index++)
					*(((PWCHAR)InforBuffer->ImageName.Buffer) + Index) = (WCHAR)pImageFileName2[Index];
			}

#ifdef _DBG
			KdPrint(("[Log] PEPROCESS: %p \n	\
					  UniqueProcessId: %x \n	\
					  ImageFileName: %wZ \n ",	\
					  InforBuffer->pEprocess,	\
					  InforBuffer->UniqueProcessId,	\
					  &InforBuffer->ImageName));
#endif
			Total += InforBuffer->ImageName.MaximumLength;

			// Next Process
			InforBuffer = (PSYSTEM_PROCESS_INFORMATION)((DWORD64)ProcessInfo + Total);
			Next = Next->Flink;
		}
		status = STATUS_SUCCESS;
	}
	else // calc total process information length
	{
		Total = 0;
		Next = ActiveProcessList->Flink;
		while (Next != ActiveProcessList)
		{
			Total += sizeof(SYSTEM_PROCESS_INFORMATION);
			// get file name length
			pEprocess = (PEPROCESS)((DWORD64)Next - ListOffset);
			pImageFileName = (PUNICODE_STRING)(*(PDWORD64)((DWORD64)pEprocess + ImageFileNameOffset));
			if (pImageFileName != NULL && pImageFileName->Buffer != NULL)
			{
				Total += pImageFileName->MaximumLength;
			}
			else
			{
				Total += 16*sizeof(WCHAR);
			}
			// next process
			Next = Next->Flink;
		}
		*OutLength = Total;
		status = STATUS_INFO_LENGTH_MISMATCH;
	}

	// UnLock Process List
	if(NtInformations.pPspActiveProcessMutex)
		KeReleaseGuardedMutexUnsafe(NtInformations.pPspActiveProcessMutex);
	else if(NtInformations.pPspActiveProcessLock)
		ExfReleasePushLockShared(NtInformations.pPspActiveProcessLock);

	KeLeaveGuardedRegion();
	return status;
}

BOOLEAN NtExGetProcessFileName(PEPROCESS pEprocess,PUNICODE_STRING pImageFileName)
{
	INT16 NameOffset;
	PUNICODE_STRING Name;
	if(pEprocess != NULL && pImageFileName != NULL)
	{
		if(NtStructInformations.Offset_SeAuditProcessCreationInfo_EPROCESS != 0xffff)
		{
			NameOffset = NtStructInformations.Offset_SeAuditProcessCreationInfo_EPROCESS;
			Name = (PUNICODE_STRING)(*(PDWORD64)((DWORD64)pEprocess + NameOffset));
			if(Name != NULL && Name->Buffer != NULL && Name->Length != 0)
			{
				pImageFileName->Buffer = ExAllocatePool(NonPagedPool,Name->MaximumLength);
				pImageFileName->Length = Name->Length;
				pImageFileName->MaximumLength = Name->MaximumLength;
				RtlZeroMemory(pImageFileName->Buffer,Name->MaximumLength);
				RtlCopyMemory(pImageFileName->Buffer,Name->Buffer,Name->Length);
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOLEAN NtExGetProcessFileNameByHandle(HANDLE ProcessHandle, PUNICODE_STRING pImageFileName)
{
	PEPROCESS pEprocess;
	
	if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle,
											 GENERIC_ALL,
											 *PsProcessType,
											 KernelMode, &pEprocess,
											 NULL)))
	{
		ObDereferenceObject(pEprocess);
		return NtExGetProcessFileName(pEprocess, pImageFileName);
	}
	return FALSE;
}

PVOID NtExGetObjectType(PVOID Object)
{
	INT16 IndexOffset;
	DWORD32 SizeOfObjHead;
	INT8 TypeIndex;
	INT8 Cookie;
	INT8 IndexOfTable;
	KdBreakPoint();

	if ((NtInformations.pObHeaderCookie != NULL) && (NtInformations.ObTypeIndexTable != NULL))
	{
		Cookie = *(NtInformations.pObHeaderCookie);
		if (Object != NULL)
		{
			if (NtStructInformations.Struct_Header_OBJECT_HEADER != NULL &&
				NtStructInformations.Offset_TypeIndex_OBJECT_HEADER != 0xffff)
			{
				//
				//	+0x0		   ObjectHeader	_OBJECT_HEADER
				//  +SizeOfObjHead Object		PVOID
				//

				SizeOfObjHead = NtStructInformations.Struct_Header_OBJECT_HEADER->TypeLength - sizeof(PVOID);
				IndexOffset = NtStructInformations.Offset_TypeIndex_OBJECT_HEADER;
				if (SizeOfObjHead)
				{
					//
					// Get Object typeindex
					//

					TypeIndex = *(PINT8)((PCHAR)Object - SizeOfObjHead + IndexOffset);

					//
					// ObTypeIndexTable[ObHeaderCookie ^ TypeIndex ^ (INT8)((Object - SizeOfObjHead) >> 8)];
					//

					IndexOfTable = Cookie ^ TypeIndex ^ (INT8)(((ULONG_PTR)((PCHAR)Object - SizeOfObjHead)) >> 8);
					return (PVOID)((PULONG_PTR)(NtInformations.ObTypeIndexTable))[IndexOfTable];
				}
			}
		}
	}
	return NULL;
}

POBJECT_HEADER_NAME_INFO NtExGetObjectNameInfo(PVOID Object){
	INT8 InfoMask;
	DWORD32 SizeOfObjHead;
	KdBreakPoint();
	if (NtInformations.pObpInfoMaskToOffset == NULL ||
		NtStructInformations.Struct_Header_OBJECT_HEADER == NULL ||
		NtStructInformations.Offset_InfoMask_OBJECT_HEADER == 0xffff)
	{
		return NULL;
	}

	if (Object != NULL)
	{
		SizeOfObjHead = NtStructInformations.Struct_Header_OBJECT_HEADER->TypeLength - sizeof(PVOID);
		InfoMask = *(PINT8)((PCHAR)Object - SizeOfObjHead + NtStructInformations.Offset_InfoMask_OBJECT_HEADER);

		if (InfoMask & 2) // have name info ?
		{
			return (POBJECT_HEADER_NAME_INFO)((PCHAR)Object - SizeOfObjHead - NtInformations.pObpInfoMaskToOffset[InfoMask & 3]);
		}
	}
	return NULL;
}

VOID NtEnumParseRootDirectory()
{
	
}
