#include "symbol_map.h"
#include <ntstrsafe.h>

BOOLEAN SymMapAllocateMap(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead)
{
	if (ppSymMapHead == NULL)
	{
		return FALSE;
	}
	
#ifdef _KERNEL_MODE
	*ppSymMapHead = (PSYMBOL_MAP_HEAD_INFO)ExAllocatePool(NonPagedPool, PAGE_SIZE);
#else
	*ppSymMapHead = (PSYMBOL_MAP_HEAD_INFO)malloc(0x1000);
#endif
	if (*ppSymMapHead == NULL)
	{
		return FALSE;
	}
#ifdef _KERNEL_MODE
	RtlZeroMemory((PVOID)*ppSymMapHead,PAGE_SIZE);
	(*ppSymMapHead)->MemorySize = PAGE_SIZE;
#else
	RtlZeroMemory((PVOID)*ppSymMapHead, 0x1000);
	(*ppSymMapHead)->MemorySize = 0x1000;
#endif
	(*ppSymMapHead)->NumberOfItem = 0;
	(*ppSymMapHead)->MemoryUsege = sizeof(SYMBOL_MAP_HEAD_INFO);
	(*ppSymMapHead)->OffsetOfItemArray = sizeof(SYMBOL_MAP_HEAD_INFO);
	(*ppSymMapHead)->SizeOfHeader = sizeof(SYMBOL_MAP_HEAD_INFO);
	(*ppSymMapHead)->OffsetOfNextItem = sizeof(SYMBOL_MAP_HEAD_INFO);
	return TRUE;
}

BOOLEAN SymMapFreeMap(PSYMBOL_MAP_HEAD_INFO pSymMapHead)
{
	if (pSymMapHead == NULL)
	{
		return FALSE;
	}
#ifdef _KERNEL_MODE
	ExFreePool((PVOID)pSymMapHead);
#else
	free((PVOID)pSymMapHead);
#endif
	return TRUE;
}

BOOLEAN SymMapExtendMap(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead)
{
	PVOID NewMap = NULL;
	if (ppSymMapHead == NULL)
	{
		return FALSE;
	}
	
#ifdef _KERNEL_MODE
	NewMap = ExAllocatePool(NonPagedPool, (*ppSymMapHead)->MemorySize + PAGE_SIZE);
	if (NewMap == NULL)
	{
		return FALSE;
	}
	RtlCopyMemory(NewMap, (PVOID)(*ppSymMapHead), (*ppSymMapHead)->MemoryUsege);
	ExFreePool((PVOID)*ppSymMapHead);
	*ppSymMapHead = (PSYMBOL_MAP_HEAD_INFO)NewMap;
	(*ppSymMapHead)->MemorySize += PAGE_SIZE;
#else
	NewMap = malloc((*ppSymMapHead)->MemorySize + 0x1000);
	if (NewMap == NULL)
	{
		return FALSE;
	}
	RtlCopyMemory(NewMap, (PVOID)*ppSymMapHead, (*ppSymMapHead)->MemoryUsege);
	free((PVOID)*ppSymMapHead);
	*ppSymMapHead = (PSYMBOL_MAP_HEAD_INFO)NewMap;
	(*ppSymMapHead)->MemorySize += 0x1000;
#endif
	(*ppSymMapHead)->OffsetOfNextItem = (*ppSymMapHead)->MemoryUsege;
	return TRUE;
}

PCHAR SymMapGetItemName(PSYMBOL_MAP_ITEM_INFO *ppItem)
{
	if (ppItem == NULL)
	{
		return NULL;
	}
	return ((PCHAR)*ppItem + (*ppItem)->NameOffset);
}

PVOID SymMapGetItemArray(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead)
{
	if (ppSymMapHead == NULL)
	{
		return NULL;
	}
	return (PVOID)((PCHAR)*ppSymMapHead + (*ppSymMapHead)->OffsetOfItemArray);
}

PVOID SymMapGetNextItem(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead)
{
	if (ppSymMapHead == NULL)
	{
		return NULL;
	}
	return (PVOID)((PCHAR)*ppSymMapHead + (*ppSymMapHead)->OffsetOfNextItem);
}

BOOLEAN SymMapInsertSymbol(PSYMBOL_MAP_HEAD_INFO *ppSymMap, PSYMBOL_INFO pSymbol, PSYMBOL_MAP_ITEM_INFO *OutItem)
{
	PSYMBOL_MAP_ITEM_INFO pItem = NULL;
	if (ppSymMap == NULL || pSymbol == NULL)
	{
		return FALSE;
	}

	if (((*ppSymMap)->MemorySize - (*ppSymMap)->MemoryUsege) < sizeof(SYMBOL_MAP_ITEM_INFO)+pSymbol->NameLen)
	{
		// Extend Map 
		if (SymMapExtendMap(ppSymMap) == FALSE)
		{
			return FALSE;
		}
	}

	// Init new item
	pItem = (PSYMBOL_MAP_ITEM_INFO)SymMapGetNextItem(ppSymMap);
	pItem->Address = pSymbol->Address;
	pItem->Flags = pSymbol->Flags;
	pItem->NameLen = pSymbol->NameLen;
	pItem->NameOffset = sizeof(SYMBOL_MAP_ITEM_INFO);
	pItem->SizeOfItem = sizeof(SYMBOL_MAP_ITEM_INFO)+pItem->NameLen;
	RtlCopyMemory((PVOID)((PCHAR)pItem + pItem->NameOffset), (PVOID)&pSymbol->Name, pSymbol->NameLen);

	// Change map header
	(*ppSymMap)->NumberOfItem++;
	(*ppSymMap)->MemoryUsege += pItem->SizeOfItem;
	(*ppSymMap)->OffsetOfNextItem = (*ppSymMap)->MemoryUsege;

	if (OutItem != NULL)
	{
		*OutItem = pItem;
	}
	return TRUE;
}

#ifdef _KERNEL_MODE
BOOLEAN SymMapLookupSymbol(PSYMBOL_MAP_HEAD_INFO *ppSymMap, PANSI_STRING Name, PSYMBOL_MAP_ITEM_INFO *ppOutSymbol)
#else
BOOLEAN SymMapLookupSymbol(PSYMBOL_MAP_HEAD_INFO *ppSymMap, PCHAR Name, PSYMBOL_MAP_ITEM_INFO *ppOutSymbol)
#endif
{
	ULONG i;
	SIZE_T MaxLength;
	SIZE_T ActualLength;
	NTSTATUS status;
	DWORD64 MapStart, MapEnd;
	ANSI_STRING SymBolName;
	PSYMBOL_MAP_ITEM_INFO pItem;

	if (ppSymMap == NULL || Name == NULL || ppOutSymbol == NULL)
	{
		return FALSE;
	}
	if ((*ppSymMap)->NumberOfItem == 0)
	{
		return FALSE;
	}
	
	// Get map start end map end
	MapStart = (DWORD64)*ppSymMap;
	MapEnd = MapStart + (*ppSymMap)->MemoryUsege;

#ifdef _KERNEL_MODE
	if (!MmIsAddressValid((PVOID)MapStart) || !MmIsAddressValid((PVOID)MapEnd))
	{
		return FALSE;
	}
#endif

	// Get Item array
	pItem = (PSYMBOL_MAP_ITEM_INFO)SymMapGetItemArray(ppSymMap);

	for (i = 0; i < (*ppSymMap)->NumberOfItem; i++)
	{
		// Init name 
		SymBolName.Buffer = (PCHAR)((PCHAR)pItem + pItem->NameOffset);

		// Name Max length in map
		MaxLength = MapEnd - (DWORD64)(SymBolName.Buffer);
		if (pItem->NameLen > MaxLength)
		{
			return FALSE;
		}

#ifdef _KERNEL_MODE

		// Check symbol name invalid
		status = RtlStringCbLengthA(SymBolName.Buffer, MaxLength, &ActualLength);
		if (status == STATUS_INVALID_PARAMETER)
		{
			// Invalid symbol map
			return FALSE;
		}
		// Invalid symbol name
		if (ActualLength != pItem->NameLen)
		{
			return FALSE;
		}
#endif

#ifdef _KERNEL_MODE
		//safe compare
		SymBolName.Length = (USHORT)ActualLength;
		SymBolName.MaximumLength = (USHORT)ActualLength;
		if(RtlCompareString(Name,&SymBolName,FALSE) == 0)
		{
			*ppOutSymbol = pItem;
			return TRUE;
		}
#else
		// un safe 
		if (memcmp((PVOID)Name, (PVOID)((PCHAR)pItem + pItem->NameOffset), pItem->NameLen) == 0)
		{
			*ppOutSymbol = pItem;
			return TRUE;
		}
#endif
		
		pItem = (PSYMBOL_MAP_ITEM_INFO)((PCHAR)pItem + pItem->SizeOfItem);
	}
	return FALSE;
}