#include "mem.h"

KIRQL Irql = 0;
KSPIN_LOCK KMemPoolBlockListLock = 0;
PMEM_BLOCK_LIST MemPoolBlockListHead = NULL;

BOOLEAN MemInitializeBlockList()
{
	if (MemPoolBlockListHead != NULL)
	{
		if (MmIsAddressValid((PVOID)MemPoolBlockListHead))
		{
			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}

	MemPoolBlockListHead = (PMEM_BLOCK_LIST)ExAllocatePool(NonPagedPool, sizeof(MEM_BLOCK_LIST));

	if (MemPoolBlockListHead == NULL) 
		return FALSE;

	RtlZeroMemory((PVOID)MemPoolBlockListHead, sizeof(MEM_BLOCK_LIST));

	InitializeListHead(&MemPoolBlockListHead->Entry);
	KeInitializeSpinLock(&KMemPoolBlockListLock);
	return TRUE;
}

BOOLEAN MemUnInitializeBlockList()
{
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemPoolBlockListHead && !IsListEmpty(&MemPoolBlockListHead->Entry))
	{
		PLIST_ENTRY NextEntry = MemPoolBlockListHead->Entry.Flink;

		while (NextEntry != &MemPoolBlockListHead->Entry)
		{
			PMEM_BLOCK_LIST Block = CONTAINING_RECORD(NextEntry, MEM_BLOCK_LIST, Entry);
			NextEntry = NextEntry->Flink;
			if (!MemFreeBlockByPoint(Block))
				continue;
		}
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
#if DBG
	ASSERT(MemPoolBlockListHead->Entry.Blink == MemPoolBlockListHead->Entry.Flink);
#endif
	ExFreePool((PVOID)MemPoolBlockListHead);
	KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
	MemPoolBlockListHead = NULL;
	return TRUE;
}

PMEM_BLOCK_LIST MemAllocateBlock(POOL_TYPE PoolType, SIZE_T Size)
{
	if (MemPoolBlockListHead && Size)
	{
		PMEM_BLOCK_LIST Block = (PMEM_BLOCK_LIST)ExAllocatePool(NonPagedPool, sizeof(MEM_BLOCK_LIST));
		if (Block == NULL) return FALSE;
		RtlZeroMemory((PVOID)Block, sizeof(MEM_BLOCK_LIST));
		Block->Buffer = ExAllocatePool(PoolType, Size);
		if (Block->Buffer == NULL)
		{
			ExFreePool((PVOID)Block);
			return NULL;
		}
		Block->Size = Size;
		Block->PoolType = PoolType;
		Block->Valid = TRUE;
		if (MemInsertBlock(Block))
		{
			return Block;
		}
		else
		{
			ExFreePool((PVOID)Block);
			return NULL;
		}
	}
	else
	{
		return NULL;
	}
}

PMEM_BLOCK_LIST MemAllocateBlockWithTag(POOL_TYPE PoolType, SIZE_T Size, ULONG Tag)
{
	if (MemPoolBlockListHead && Size && Tag)
	{
		PMEM_BLOCK_LIST Block = (PMEM_BLOCK_LIST)ExAllocatePool(NonPagedPool, sizeof(MEM_BLOCK_LIST));
		if (Block == NULL) return FALSE;
		RtlZeroMemory((PVOID)Block, sizeof(MEM_BLOCK_LIST));
		Block->Buffer = ExAllocatePoolWithTag(PoolType, Size,Tag);
		if (Block->Buffer == NULL)
		{
			ExFreePool((PVOID)Block);
			return NULL;
		}
		Block->Size = Size;
		Block->PoolType = PoolType;
		Block->Tag = Tag;
		Block->Valid = TRUE;
		if (MemInsertBlock(Block))
		{
			return Block;
		}
		else
		{
			ExFreePool((PVOID)Block);
			return NULL;
		}
	}
	else
	{
		return NULL;
	}
}

PMEM_BLOCK_LIST ExLockMemAllocateBlock(POOL_TYPE PoolType, SIZE_T Size)
{
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemPoolBlockListHead && Size)
	{
		PMEM_BLOCK_LIST Block = (PMEM_BLOCK_LIST)ExAllocatePool(NonPagedPool, sizeof(MEM_BLOCK_LIST));
		if (Block == NULL) return FALSE;
		RtlZeroMemory((PVOID)Block, sizeof(MEM_BLOCK_LIST));
		Block->Buffer = ExAllocatePool(PoolType, Size);
		if (Block->Buffer == NULL)
		{
			ExFreePool((PVOID)Block);
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return NULL;
		}
		Block->Size = Size;
		Block->PoolType = PoolType;
		Block->Valid = TRUE;
		if (MemInsertBlock(Block))
		{
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return Block;
		}
		else
		{
			ExFreePool((PVOID)Block);
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return NULL;
		}
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return NULL;
	}
}

PMEM_BLOCK_LIST ExLockMemAllocateBlockWithTag(POOL_TYPE PoolType, SIZE_T Size, ULONG Tag)
{
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemPoolBlockListHead && Size && Tag)
	{
		PMEM_BLOCK_LIST Block = (PMEM_BLOCK_LIST)ExAllocatePool(NonPagedPool, sizeof(MEM_BLOCK_LIST));
		if (Block == NULL) return FALSE;
		RtlZeroMemory((PVOID)Block, sizeof(MEM_BLOCK_LIST));
		Block->Buffer = ExAllocatePoolWithTag(PoolType, Size, Tag);
		if (Block->Buffer == NULL)
		{
			ExFreePool((PVOID)Block);
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return NULL;
		}
		Block->Size = Size;
		Block->PoolType = PoolType;
		Block->Tag = Tag;
		Block->Valid = TRUE;
		if (MemInsertBlock(Block))
		{
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return Block;
		}
		else
		{
			ExFreePool((PVOID)Block);
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return NULL;
		}
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return NULL;
	}
}

BOOLEAN MemFreeBlockByPoint(PMEM_BLOCK_LIST pBlk)
{
	if (MemDeleteBlock(pBlk))
	{
		if (pBlk->Tag)
			ExFreePoolWithTag(pBlk->Buffer, pBlk->Tag);
		else
			ExFreePool(pBlk->Buffer);
		pBlk->Valid = FALSE;
		pBlk->Buffer = NULL;
		pBlk->Size = 0;
		ExFreePool((PVOID)pBlk);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN MemFreeBlockByAddress(PVOID buffer)
{
	PMEM_BLOCK_LIST Block = NULL;
	if (MemLookupBlockByAddress(buffer, &Block) && Block)
	{
		if (MemDeleteBlock(Block))
		{
			if (Block->Tag)
				ExFreePoolWithTag(Block->Buffer, Block->Tag);
			else
				ExFreePool(Block->Buffer);
			Block->Valid = FALSE;
			Block->Buffer = NULL;
			Block->Size = 0;
			ExFreePool((PVOID)Block);
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

BOOLEAN MemFreeBlockByTag(ULONG tag)
{
	PMEM_BLOCK_LIST Block = NULL;
	if (MemLookupBlockByTag(tag, &Block) && Block)
	{
		if (MemDeleteBlock(Block))
		{
			if (Block->Tag)
				ExFreePoolWithTag(Block->Buffer, Block->Tag);
			else
				ExFreePool(Block->Buffer);
			Block->Valid = FALSE;
			Block->Buffer = NULL;
			Block->Size = 0;
			ExFreePool((PVOID)Block);
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

BOOLEAN ExLockMemFreeBlockByPoint(PMEM_BLOCK_LIST pBlk)
{
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemDeleteBlock(pBlk))
	{
		if (pBlk->Tag)
			ExFreePoolWithTag(pBlk->Buffer, pBlk->Tag);
		else
			ExFreePool(pBlk->Buffer);
		pBlk->Valid = FALSE;
		pBlk->Buffer = NULL;
		pBlk->Size = 0;
		ExFreePool((PVOID)pBlk);
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return TRUE;
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
}

BOOLEAN ExLockMemFreeBlockByAddress(PVOID buffer)
{
	PMEM_BLOCK_LIST Block;
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemLookupBlockByAddress(buffer, &Block) && Block)
	{
		if (MemDeleteBlock(Block))
		{
			if (Block->Tag)
				ExFreePoolWithTag(Block->Buffer, Block->Tag);
			else
				ExFreePool(Block->Buffer);
			Block->Valid = FALSE;
			Block->Buffer = NULL;
			Block->Size = 0;
			ExFreePool((PVOID)Block);
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return TRUE;
		}
		else
		{
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return FALSE;
		}
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
}

BOOLEAN ExLockMemFreeBlockByTag(ULONG tag)
{
	PMEM_BLOCK_LIST Block;
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemLookupBlockByTag(tag, &Block) && Block)
	{
		if (MemDeleteBlock(Block))
		{
			if (Block->Tag)
				ExFreePoolWithTag(Block->Buffer, Block->Tag);
			else
				ExFreePool(Block->Buffer);
			Block->Valid = FALSE;
			Block->Buffer = NULL;
			Block->Size = 0;
			ExFreePool((PVOID)Block);
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return TRUE;
		}
		else
		{
			KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
			return FALSE;
		}
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
}

BOOLEAN MemInsertBlock(PMEM_BLOCK_LIST pBlk)
{
	if (pBlk && pBlk->Buffer && pBlk->Size && pBlk->Valid)
	{
		InsertHeadList(&MemPoolBlockListHead->Entry, &pBlk->Entry);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN MemDeleteBlock(PMEM_BLOCK_LIST pBlk)
{
	if (MemPoolBlockListHead && pBlk && pBlk->Buffer && pBlk->Size && pBlk->Valid)
	{
		RemoveEntryList(&pBlk->Entry);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN MemLookupBlockByAddress(PVOID buffer, PMEM_BLOCK_LIST *pBlk)
{
	if (MemPoolBlockListHead && buffer && !IsListEmpty(&MemPoolBlockListHead->Entry))
	{
		PLIST_ENTRY NextEntry = MemPoolBlockListHead->Entry.Flink;

		while (NextEntry != &MemPoolBlockListHead->Entry)
		{
			PMEM_BLOCK_LIST Block = CONTAINING_RECORD(NextEntry, MEM_BLOCK_LIST, Entry);
			if (Block->Buffer == buffer)
			{
				*pBlk = Block;
				return TRUE;
			}
			NextEntry = NextEntry->Flink;
		}
		return FALSE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN MemLookupBlockByTag(ULONG tag, PMEM_BLOCK_LIST *pBlk)
{
	if (MemPoolBlockListHead && !IsListEmpty(&MemPoolBlockListHead->Entry))
	{
		PLIST_ENTRY NextEntry = MemPoolBlockListHead->Entry.Flink;

		while (NextEntry != &MemPoolBlockListHead->Entry)
		{
			PMEM_BLOCK_LIST Block = CONTAINING_RECORD(NextEntry, MEM_BLOCK_LIST, Entry);
			if (Block->Tag == tag)
			{
				*pBlk = Block;
				return TRUE;
			}
			NextEntry = NextEntry->Flink;
		}
		return FALSE;
	}
	else
	{
		return FALSE;
	}
}

BOOLEAN ExLockMemLookupBlockByAddress(PVOID buffer, PMEM_BLOCK_LIST * pBlk)
{
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemPoolBlockListHead && buffer && !IsListEmpty(&MemPoolBlockListHead->Entry))
	{
		PLIST_ENTRY NextEntry = MemPoolBlockListHead->Entry.Flink;

		while (NextEntry != &MemPoolBlockListHead->Entry)
		{
			PMEM_BLOCK_LIST Block = CONTAINING_RECORD(NextEntry, MEM_BLOCK_LIST, Entry);
			if (Block->Buffer == buffer)
			{
				*pBlk = Block;
				KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
				return TRUE;
			}
			NextEntry = NextEntry->Flink;
		}
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
}

BOOLEAN ExLockMemLookupBlockByTag(ULONG tag, PMEM_BLOCK_LIST * pBlk)
{
	KeAcquireSpinLock(&KMemPoolBlockListLock, &Irql);
	if (MemPoolBlockListHead && !IsListEmpty(&MemPoolBlockListHead->Entry))
	{
		PLIST_ENTRY NextEntry = MemPoolBlockListHead->Entry.Flink;

		while (NextEntry != &MemPoolBlockListHead->Entry)
		{
			PMEM_BLOCK_LIST Block = CONTAINING_RECORD(NextEntry, MEM_BLOCK_LIST, Entry);
			if (Block->Tag == tag)
			{
				*pBlk = Block;
				KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
				return TRUE;
			}
			NextEntry = NextEntry->Flink;
		}
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
	else
	{
		KeReleaseSpinLock(&KMemPoolBlockListLock, Irql);
		return FALSE;
	}
}
