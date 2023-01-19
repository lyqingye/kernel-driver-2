#include "hook.h"
#include "trampoline.h"

INLINE_HOOK_INFO_TABLE HkInlineHookInfoTable;

#pragma alloc_text(PAGE,HkInitializaInlineHook)
#pragma alloc_text(PAGE,HkUnInitializaInlineHook)
#pragma alloc_text(PAGE,HkCreateInlineHook)
#pragma alloc_text(PAGE,HkRemoveInlineHook)
#pragma alloc_text(PAGE,HkCreateInlineHookEntry)
#pragma alloc_text(PAGE,HkDeleteInlineHookEntry)
#pragma alloc_text(PAGE,HkLookupInlineHookEntryByHandle)
#pragma alloc_text(PAGE,HkLookupInlineHookEntryByTarget)
#pragma alloc_text(PAGE,HkGetFreeInlineHookEntryHandle)
#pragma alloc_text(PAGE,HkArrangeInlineHookInfoTable)
#pragma alloc_text(PAGE,HkLockInlineHookTablePage)
#pragma alloc_text(PAGE,HkUnLockInlineHookTablePage)
#pragma alloc_text(PAGE,HkLockInlineHookEntryPage)
#pragma alloc_text(PAGE,HkUnLockInlineHookEntryPage)

BOOLEAN HkInitializaInlineHook()
{
	PAGED_CODE();

	RtlZeroMemory((PVOID)&HkInlineHookInfoTable, sizeof(INLINE_HOOK_INFO_TABLE));

	//
	// Allocate Inline Hook Table
	// This table use to storage Inline Hook Entry .

	HkInlineHookInfoTable.pEntryTable = ExLockMemAllocateBlock(PagedPool, HOOK_TABLE_SIZE);

	if (HkInlineHookInfoTable.pEntryTable == NULL)
	{
		return FALSE;
	}

	//
	// Allocate Trampo Line , Restore instruction And Springboard
	// Target -> TrampoLine -> Detour  Or  Ordlinal -> TrampoLine -> Target
	// TramPolineBlock must be Allocate in NonPagedPool

	//HkInlineHookInfoTable.TramPolineBlock = ExLockMemAllocateBlock(NonPagedPool, HOOK_TRAMPO_LINE_SIZE);

	//if (HkInlineHookInfoTable.TramPolineBlock == NULL)
	//{
	//	MemFreeBlockByPoint(HkInlineHookInfoTable.pEntryTable);
	//	return FALSE;
	//}

	//
	// set TramPolineBlock use count
	//

	//HkInlineHookInfoTable.BlockCount = 0;
	RtlZeroMemory(HkInlineHookInfoTable.pEntryTable->Buffer, PAGE_SIZE);

	//
	// Fill int3 in trampoline
	// 

	//RtlFillMemory(HkInlineHookInfoTable.TramPolineBlock->Buffer,PAGE_SIZE,0xCC);

	//
	// Set Hook Entry Pointer
	//

	HkInlineHookInfoTable.pItemsEntry = (PMEM_BLOCK_LIST *)HkInlineHookInfoTable.pEntryTable->Buffer;

	//
	// Inline Hook Table Level
	// Support Level 1	

	HkInlineHookInfoTable.Level = HOOK_SUPORT_TABLE_LEVEL;

	//
	// Init Table Lock will resets the IRQL DISPATCH_LEVEL,And Table Use PagedPool 
	// So the code that uses the lock is as small as possible,see following function list
	//
	// HkCreateInlineHookEntry
	// HkDeleteInlineHookEntry
	// HkLookupInlineHookEntryByHandle
	// HkLookupInlineHookEntryByTarget
	//
	// If access Hook Entry (not table) And IRQL=DISPATCH_LEVEL,you must use mdl lock Entry

	KeInitializeSpinLock(&HkInlineHookInfoTable.LookupLock);
	return TRUE;
}

BOOLEAN HkUnInitializaInlineHook()
{
	HKHANDLE Handle;

	PAGED_CODE();

	if (HkInlineHookInfoTable.pEntryTable == NULL ||
		HkInlineHookInfoTable.pItemsEntry == NULL 
		//HkInlineHookInfoTable.TramPolineBlock == NULL
		)
	{
		return FALSE;
	}

	//
	// frequently Create And Delete Hook Entry will Create holes in Table
	// must iteration all item in table 

	for (Handle = 0; Handle < HOOK_MAX_ENTRY_NUMBER; Handle++)
	{
		if (HkRemoveInlineHook(Handle) == FALSE)
		{
			//
			// Handle may be invalid,remove next
			//

			continue;
		}
	}
	
	//
	// Free Table And trampoline block,don't use check result 
	// Memory manage can be release at memory manage exit  
	
	ExLockMemFreeBlockByPoint(HkInlineHookInfoTable.pEntryTable);
	//ExLockMemFreeBlockByPoint(HkInlineHookInfoTable.TramPolineBlock);
	
	return TRUE;
}

BOOLEAN HkCreateInlineHook(PVOID pTarget, PVOID pDetour, PVOID * ppOriginal, PHKHANDLE pOutHandle)
{
	TRAMPOLINE TramPoline;
	PINLINE_HOOK_ENTRY pNewHookEntry = NULL;

	PAGED_CODE();

	if (pTarget == NULL || pDetour == NULL || ppOriginal == NULL || pOutHandle == NULL)
	{
		return FALSE;
	}

	// 
	// Trampoline block Deplete
	//

	//if (HkInlineHookInfoTable.BlockCount >= HOOK_TRAMPO_LINE_SIZE)
	//{
	//	return FALSE;
	//}

	//
	// Create HooK Entry
	//

	if (HkCreateInlineHookEntry(&pNewHookEntry))
	{

#if DBG
		ASSERT(pNewHookEntry->isEnabled == FALSE);
		ASSERT(pNewHookEntry->Handle != HK_INVALID_HANDLE_VALUE);
#endif 
		RtlZeroMemory((PVOID)&TramPoline, sizeof(TRAMPOLINE));

		// 
		// Set trampoline
		//

		TramPoline.pTarget = pTarget;
		TramPoline.pDetour = pDetour;
		//TramPoline.pTrampoline = (PVOID)(((PUCHAR)(HkInlineHookInfoTable.TramPolineBlock->Buffer)) +
		//								 HkInlineHookInfoTable.BlockCount);
		TramPoline.pTrampoline = ExLockMemAllocateBlock(NonPagedPool,256)->Buffer;

		//
		// Create Trampoline
		//

		if (HkUnitCreateTramPoline(&TramPoline))
		{
			//
			// Copy trampoline information
			//

			pNewHookEntry->pTrampoline = TramPoline.pTrampoline;
			pNewHookEntry->pTarget = TramPoline.pTarget;
			pNewHookEntry->pDetour = TramPoline.pRelay;
			pNewHookEntry->nIP = TramPoline.nIP;

			//
			// backup covered instructions
			//

			RtlCopyMemory((PVOID)&pNewHookEntry->oldIPs[0], (PVOID)&TramPoline.oldIPs[0], sizeof(pNewHookEntry->oldIPs));
			RtlCopyMemory((PVOID)&pNewHookEntry->newIPs[0], (PVOID)&TramPoline.newIPs[0], sizeof(pNewHookEntry->newIPs));

			//
			// return Hook entry handle,And orginal function address
			//

			*pOutHandle = pNewHookEntry->Handle;
			*ppOriginal = pNewHookEntry->pTrampoline;

			//
			// Set trampoline use count
			//

			//HkInlineHookInfoTable.BlockCount += TramPoline.sizeTramPoline;
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN HkEnableInlineHook(HKHANDLE Handle)
{
	PMDL pMdl;
	PJMP_ABS pJmp;
	PINLINE_HOOK_ENTRY pHookEntry;
	INLINE_HOOK_ENTRY CaptureHookInfo;
	
	//
	// lookup hook entry
	//

	if (HkLookupInlineHookEntryByHandle(&pHookEntry, Handle))
	{

#if DBG
		ASSERT(pHookEntry != NULL);
#endif
		//
		// Hook is enable
		//

		if (pHookEntry->isEnabled)
		{
			return FALSE;
		}
		
		//
		// Lock Page begin Raise IRQL to DISPATCH_LEVEL
		// And Capture hook entry information

		HkLockInlineHookEntryPage(pHookEntry,&pMdl);

		//
		// Copy Hook Information 
		// Why? This function at nonepaged pool,And pHookEntry at paged pool,And IRQL=DISPATCH_LEVEL
		// So must copy Hook Information

		pJmp = (PJMP_ABS)pHookEntry->pTarget;
		RtlCopyMemory((PVOID)&CaptureHookInfo, pHookEntry, sizeof(INLINE_HOOK_ENTRY));

		//
		// Raise IRQL to DISPATCH_LEVEL,because pHookEntry Allocate in PagedPool so 
		// must be get variable from pHookEntry.
		// 
		
		HkUnitWriteProtectOff();
		try
		{
			//
			// Backup Original instruction 
			//

			RtlCopyMemory((PVOID)&CaptureHookInfo.backup, CaptureHookInfo.pTarget, sizeof(JMP_ABS));

			//
			// JMP[imm64]
			//

			pJmp->opcode0 = 0xff;
			pJmp->opcode1 = 0x25;
			pJmp->dummy = 0x00000000;
			pJmp->address = (UINT64)CaptureHookInfo.pDetour;
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			return FALSE;
		}

		//
		// Lower IRQL
		//

		HkUnitWriteProtectOn();

		//
		// Set hook information
		//

		RtlCopyMemory((PVOID)&pHookEntry->backup,(PVOID)&CaptureHookInfo.backup,sizeof(JMP_ABS));
		pHookEntry->isEnabled = TRUE;

		//
		// Unlock hook entry page
		//

		HkUnLockInlineHookEntryPage(pMdl);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN HkRemoveInlineHook(HKHANDLE Handle)
{
	PINLINE_HOOK_ENTRY pHookEntry = NULL;

	PAGED_CODE();

	//
	// lookup hook entry
	//

	if (HkLookupInlineHookEntryByHandle(&pHookEntry, Handle))
	{

#if DBG
		ASSERT(pHookEntry != NULL);
#endif

		//
		// disable hook if hook enable
		//

		if (pHookEntry->isEnabled)
		{
			if (!HkDisableInlineHook(Handle))
			{
				return FALSE;
			}
		}
		
		//
		// Free TrampeLine
		//

		if(ExLockMemFreeBlockByAddress(pHookEntry->pTrampoline) == FALSE)
		{
			return FALSE;
		}

		//
		// Delete hook entry
		//

		return HkDeleteInlineHookEntry(pHookEntry);
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN HkDisableInlineHook(HKHANDLE Handle)
{
	PMDL pMdl;
	PINLINE_HOOK_ENTRY pHookEntry = NULL;
	INLINE_HOOK_ENTRY CaptureHookInfo;

	//
	// lookup hook entry
	//

	if (HkLookupInlineHookEntryByHandle(&pHookEntry, Handle))
	{

#if DBG
		ASSERT(pHookEntry != NULL);
#endif

		if (pHookEntry->isEnabled == FALSE)
		{
			return TRUE;
		}

		//
		// Lock Page begin Raise IRQL to DISPATCH_LEVEL
		// And Capture hook entry information

		HkLockInlineHookEntryPage(pHookEntry,&pMdl);

		//
		// Copy Hook Information 
		// Why? This function at nonepaged pool,And pHookEntry at paged pool,And IRQL=DISPATCH_LEVEL
		// So must copy Hook Information

		RtlCopyMemory((PVOID)&CaptureHookInfo, pHookEntry, sizeof(INLINE_HOOK_ENTRY));

		//
		// Raise IRQL to DISPATCH_LEVEL,because pHookEntry Allocate in PagedPool so 
		// must be get variable from pHookEntry.
		// 

		HkUnitWriteProtectOff();

		//	
		// recovery function
		//

		RtlCopyMemory(CaptureHookInfo.pTarget, (PVOID)&CaptureHookInfo.backup, sizeof(JMP_ABS));
		
		//
		// Lower IRQL
		//

		HkUnitWriteProtectOn();

		pHookEntry->isEnabled = FALSE;

		//
		// Unlock hook entry page
		//

		HkUnLockInlineHookEntryPage(pMdl);

		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN HkCreateInlineHookEntry(PINLINE_HOOK_ENTRY * ppNewInlineHookEntry)
{
	PMDL pMdl;
	HKHANDLE FreeHandle;
	PMEM_BLOCK_LIST NewEntry = NULL;
	
	PAGED_CODE();

	if (HkInlineHookInfoTable.pEntryTable == NULL || ppNewInlineHookEntry == NULL)
		return FALSE;

	//
	// Allocate new hook entry
	//

	NewEntry = MemAllocateBlock(PagedPool, HOOK_HOOK_ENTRY_SIZE);

	if (NewEntry == NULL)
	{
		return FALSE;
	}

	//
	// Add Allocate count
	//

	HkInlineHookInfoTable.Numbers++;
	HkInlineHookInfoTable.AllocCount++;

	//
	// Lock table 
	//
	HkLockInlineHookTablePage(&pMdl);

	//
	// Get free handle in table
	//

	FreeHandle = HkGetFreeInlineHookEntryHandle();

	//
	// if no free handle then arrange table And retry get free handle
	//

	if (FreeHandle == -1)
	{
		if (HkArrangeInlineHookInfoTable())
		{
			FreeHandle = HkGetFreeInlineHookEntryHandle();
			if (FreeHandle == -1)
			{
				//
				// no free handle
				//

				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}

	KeAcquireSpinLock(&HkInlineHookInfoTable.LookupLock, &HkInlineHookInfoTable.Irql);

	//
	// save entry
	//

	HkInlineHookInfoTable.pItemsEntry[FreeHandle] = NewEntry;

	//
	// Unlock table
	//

	KeReleaseSpinLock(&HkInlineHookInfoTable.LookupLock, HkInlineHookInfoTable.Irql);
	HkUnLockInlineHookTablePage(pMdl);

	//
	// Set new hook entry
	//

	RtlZeroMemory(NewEntry->Buffer, HOOK_HOOK_ENTRY_SIZE);

	try
	{
		*ppNewInlineHookEntry = (PINLINE_HOOK_ENTRY)NewEntry->Buffer;
		(*ppNewInlineHookEntry)->Handle = FreeHandle;
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	return TRUE;
}

BOOLEAN HkDeleteInlineHookEntry(PINLINE_HOOK_ENTRY ppInlineHookEntry)
{
	PMDL pMdl;
	PMEM_BLOCK_LIST pBlock;

	PAGED_CODE();
	
	if(HkInlineHookInfoTable.pEntryTable == NULL || ppInlineHookEntry == NULL || ppInlineHookEntry->isEnabled)
		return FALSE;

	//
	// Lock Table
	//

	HkLockInlineHookTablePage(&pMdl);
	KeAcquireSpinLock(&HkInlineHookInfoTable.LookupLock, &HkInlineHookInfoTable.Irql);

	//
	// Remove hook entry
	//

	pBlock = HkInlineHookInfoTable.pItemsEntry[ppInlineHookEntry->Handle];
	HkInlineHookInfoTable.pItemsEntry[ppInlineHookEntry->Handle] = NULL;

	//
	// Set free count
	//

	HkInlineHookInfoTable.FreeCount++;
	HkInlineHookInfoTable.Numbers--;

	//
	// Unlock table
	//

	KeReleaseSpinLock(&HkInlineHookInfoTable.LookupLock, HkInlineHookInfoTable.Irql);
	HkUnLockInlineHookTablePage(pMdl);

	return MemFreeBlockByPoint(pBlock);
}

BOOLEAN HkLookupInlineHookEntryByHandle(PINLINE_HOOK_ENTRY * ppNewInlineHookEntry, HKHANDLE Handle)
{
	PMDL pMdl;
	PMEM_BLOCK_LIST pItem;

	PAGED_CODE();

	if (HkInlineHookInfoTable.pEntryTable == NULL || ppNewInlineHookEntry == NULL || Handle <= HK_INVALID_HANDLE_VALUE)
		return FALSE;

	//
	// Lock Table
	//

	HkLockInlineHookTablePage(&pMdl);
	KeAcquireSpinLock(&HkInlineHookInfoTable.LookupLock, &HkInlineHookInfoTable.Irql);

	//
	// Get hook entry
	//

	pItem = HkInlineHookInfoTable.pItemsEntry[Handle];

	//
	// Unlock table
	//

	KeReleaseSpinLock(&HkInlineHookInfoTable.LookupLock, HkInlineHookInfoTable.Irql);
	HkUnLockInlineHookTablePage(pMdl);

	if (pItem == NULL)
	{
		return FALSE;
	}
	else
	{	
		*ppNewInlineHookEntry = (PINLINE_HOOK_ENTRY)pItem->Buffer;
		return (*ppNewInlineHookEntry)->Handle == Handle;
	}
}

BOOLEAN HkLookupInlineHookEntryByTarget(PINLINE_HOOK_ENTRY *ppNewInlineHookEntry, PVOID pTarget)
{
	PMDL pMdl;
	HKHANDLE Handle;
	PMEM_BLOCK_LIST pItem;
	PINLINE_HOOK_ENTRY pEntry;

	PAGED_CODE();

	if (HkInlineHookInfoTable.pEntryTable == NULL || ppNewInlineHookEntry == NULL || pTarget == NULL)
		return FALSE;

	for (Handle = 0; Handle < HOOK_MAX_ENTRY_NUMBER; Handle++)
	{
		//
		// Lock Table
		//

		HkLockInlineHookTablePage(&pMdl);
		KeAcquireSpinLock(&HkInlineHookInfoTable.LookupLock, &HkInlineHookInfoTable.Irql);

		pItem = HkInlineHookInfoTable.pItemsEntry[Handle];

		//
		// Unlock table
		//

		KeReleaseSpinLock(&HkInlineHookInfoTable.LookupLock, HkInlineHookInfoTable.Irql);
		HkUnLockInlineHookTablePage(pMdl);

		//
		// Lock hook entry
		//

		HkLockInlineHookEntryPage(pEntry, &pMdl);
		if (pItem != NULL)
		{
			pEntry = (PINLINE_HOOK_ENTRY)pItem->Buffer;
			if (pEntry->pTarget == pTarget)
			{
				*ppNewInlineHookEntry = pEntry;
				return TRUE;
			}
		}

		//
		// Unlock hook entry
		//

		HkUnLockInlineHookEntryPage(pMdl);
	}
	return FALSE;
}

VOID HkLockInlineHookTablePage(PMDL *ppMdl)
{
	PAGED_CODE();

	//
	// Allocate mdl
	//

	*ppMdl = IoAllocateMdl((PVOID)HkInlineHookInfoTable.pItemsEntry,
						   HOOK_TABLE_SIZE, FALSE, FALSE, NULL);
	
	//
	// Lock page
	//

	if(*ppMdl != NULL)
	{
		try
		{
			MmProbeAndLockPages(*ppMdl, KernelMode, IoModifyAccess);
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
	}
}

VOID HkUnLockInlineHookTablePage(PMDL pMdl)
{
	PAGED_CODE();

	//
	// Unlock pages
	//

	MmUnlockPages(pMdl);

	//
	// Free mdl
	//

	IoFreeMdl(pMdl);
}

VOID HkLockInlineHookEntryPage(PINLINE_HOOK_ENTRY pEntry,PMDL *ppMdl)
{
	PAGED_CODE();

	//
	// Allocate mdl
	//

	*ppMdl = IoAllocateMdl((PVOID)pEntry, sizeof(INLINE_HOOK_ENTRY),
						   FALSE, FALSE, NULL);

	//
	// Lock page
	//

	if(*ppMdl != NULL)
	{
		try
		{
			MmProbeAndLockPages(*ppMdl, KernelMode, IoModifyAccess);
		}
		except(EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
	}					   
}

VOID HkUnLockInlineHookEntryPage(PMDL pMdl)
{
	PAGED_CODE();

	//
	// Unlock pages
	//

	MmUnlockPages(pMdl);

	//
	// Free mdl
	//

	IoFreeMdl(pMdl);
}

HKHANDLE HkGetFreeInlineHookEntryHandle()
{
	PAGED_CODE();

	if (HkInlineHookInfoTable.pEntryTable == NULL)
	{
		return HK_INVALID_HANDLE_VALUE;
	}	
	else
	{
		//
		// arrange table
		//

		HkArrangeInlineHookInfoTable();
		return HkInlineHookInfoTable.FreeEntry;
	}	
}

BOOLEAN HkArrangeInlineHookInfoTable()
{
	HKHANDLE FreeHandle;

	PAGED_CODE();

	if (HkInlineHookInfoTable.pEntryTable == NULL)
		return FALSE;

	//
	// No Free Handle
	//

	if (HkInlineHookInfoTable.Numbers == HOOK_MAX_ENTRY_NUMBER)
		return FALSE;

	//
	// Free Handle Valid ?
	//

	if (HkInlineHookInfoTable.pItemsEntry[HkInlineHookInfoTable.FreeEntry] == NULL)
		return TRUE;
	
	//
	// Next Free Handle Valid ?
	//

	if (HkInlineHookInfoTable.FreeEntry < HOOK_MAX_ENTRY_NUMBER - 1)
	{
		if (HkInlineHookInfoTable.pItemsEntry[HkInlineHookInfoTable.FreeEntry + 1] == NULL)
		{
			HkInlineHookInfoTable.FreeEntry++;
			return TRUE;
		}
	}

	//
	// Next Free Handle Invalid,iteration table get free handle
	//

	for (FreeHandle = 0; FreeHandle < HOOK_MAX_ENTRY_NUMBER; FreeHandle++)
	{
		if (HkInlineHookInfoTable.pItemsEntry[FreeHandle] == NULL)
		{
			HkInlineHookInfoTable.FreeEntry = FreeHandle;
			return TRUE;
		}
	}
	return FALSE;
}

#pragma intrinsic(__readmsr)

VOID HkUnitWriteProtectOff()
{
	ULONG64 cr0;
	Irql = KeRaiseIrqlToDpcLevel();
	cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
}

VOID HkUnitWriteProtectOn()
{
	ULONG64 cr0;
	cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(Irql);
}
