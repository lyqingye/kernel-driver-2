
#ifndef MEM_HEAD
#define MEM_HEAD

#include "pstdint.h"

#pragma warning(disable:4996) 

#pragma once

// Memory block description.
typedef struct _MEM_BLOCK_LIST {
	LIST_ENTRY Entry;	// List Entry
	POOL_TYPE PoolType; // Pool Type
	ULONG Tag;			// Pool Tag
	PVOID Buffer;		// Buffer Address
	SIZE_T Size;		// Buffer Size
	BOOLEAN Valid;		// Block is Valid
}MEM_BLOCK_LIST,*PMEM_BLOCK_LIST;

// Global variable Irql.
// Your program must be use only a Block List.
EXTERN_C KIRQL Irql;

// Global variable Lock
EXTERN_C KSPIN_LOCK KMemPoolBlockListLock;

// Global variable Memory Block List Header.
EXTERN_C PMEM_BLOCK_LIST MemPoolBlockListHead;

// Initialization Memory Block List.
// Parameters:
//		None
// Return Value:
//		TRUE		Initalization Success.
//		FALSE		Initalization Faild.
BOOLEAN __fastcall MemInitializeBlockList();

// UnInitialization Memory Block List.
// Parameters:
//		None
// Return Value:
//		TRUE		UnInitalization Success.
//		FALSE		UnInitalization Faild.
BOOLEAN __fastcall MemUnInitializeBlockList();

// Allocate Memory unsafe, don't use lock.
// Parameters:
//		PoolType		[In]	Pool Type
//		Size			[In]	Buffer size
// Return Value:
//		NULL			Allocate Faild.
//		NOT NULL		Allocate Sucess.	
PMEM_BLOCK_LIST __fastcall MemAllocateBlock(POOL_TYPE PoolType, SIZE_T Size);

// Allocate Memory with tag unsafe, don't use lock
// Parameters:
//		PoolType		[In]	Pool Type
//		Size			[In]	Buffer size
//		Tag				[In]	Buffer tag
// Return Value:
//		NULL			Allocate Faild.
//		NOT NULL		Allocate Sucess.	
PMEM_BLOCK_LIST __fastcall MemAllocateBlockWithTag(POOL_TYPE PoolType, SIZE_T Size, ULONG Tag);

// Allocate Memory use lock
// Parameters:
//		PoolType		[In]	Pool Type
//		Size			[In]	Buffer size
// Return Value:
//		NULL			Allocate Faild.
//		NOT NULL		Allocate Sucess.	
PMEM_BLOCK_LIST __fastcall ExLockMemAllocateBlock(POOL_TYPE PoolType, SIZE_T Size);

// Allocate Memory with tag And use lock
// Parameters:
//		PoolType		[In]	Pool Type
//		Size			[In]	Buffer size
//		Tag				[In]	Buffer tag
// Return Value:
//		NULL			Allocate Faild.
//		NOT NULL		Allocate Sucess.	
PMEM_BLOCK_LIST __fastcall ExLockMemAllocateBlockWithTag(POOL_TYPE PoolType, SIZE_T Size, ULONG Tag);

// Free Memory by use block pointer
// Unsafe
// Parameters:
//		pBlk			[In]	Memory Block
BOOLEAN __fastcall MemFreeBlockByPoint(PMEM_BLOCK_LIST pBlk);

// Free Memory by use buffer address 
// Unsafe
// Parameters:
//		buffer			[In]	Buffer address
BOOLEAN __fastcall MemFreeBlockByAddress(PVOID buffer);

// Free Memory by use buffer tag
// Unsafe
// Only free first match block
// Parameters:
//		tag				[In]	Buffer tag
BOOLEAN __fastcall MemFreeBlockByTag(ULONG tag);

// Free Memory by use block pointer
// Use lock
// Parameters:
//		pBlk			[In]	Memory Block
BOOLEAN __fastcall ExLockMemFreeBlockByPoint(PMEM_BLOCK_LIST pBlk);

// Free Memory by use buffer address 
// Use lock
// Parameters:
//		buffer			[In]	Buffer address
BOOLEAN __fastcall ExLockMemFreeBlockByAddress(PVOID buffer);

// Free Memory by use buffer tag
// Use lock
// Only free first match block
// Parameters:
//		tag				[In]	Buffer tag
BOOLEAN __fastcall ExLockMemFreeBlockByTag(ULONG tag);

// Insert Block to global block list
// This function doesn't public because unsafe
BOOLEAN __fastcall MemInsertBlock(PMEM_BLOCK_LIST pBlk);

// Delete Block from global block list
// This function doesn't public because unsafe
BOOLEAN __fastcall MemDeleteBlock(PMEM_BLOCK_LIST pBlk);

// Lookup block by use buffer address
// unsafe
// Parameters:
//		buffer			[In]	buffer address
//		pBlk			[Out]	A pointer to be memory block
BOOLEAN __fastcall MemLookupBlockByAddress(PVOID buffer, PMEM_BLOCK_LIST *pBlk);

// Lookup block by use buffer tag
// unsafe
// Parameters:
//		tag				[In]	buffer tag
//		pBlk			[Out]	A pointer to be memory block
BOOLEAN __fastcall MemLookupBlockByTag(ULONG tag, PMEM_BLOCK_LIST *pBlk);

// Lookup block by use buffer address
// Use lock
// Parameters:
//		buffer			[In]	buffer address
//		pBlk			[Out]	A pointer to be memory block
BOOLEAN __fastcall ExLockMemLookupBlockByAddress(PVOID buffer, PMEM_BLOCK_LIST *pBlk);

// Lookup block by use buffer tag
// Use lock
// Parameters:
//		tag				[In]	buffer tag
//		pBlk			[Out]	A pointer to be memory block
BOOLEAN __fastcall ExLockMemLookupBlockByTag(ULONG tag, PMEM_BLOCK_LIST *pBlk);

#endif