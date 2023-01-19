
/*++

Module Name:

	hook.h 

	Description:

		Kernel Inline Hook Engine

		This Engine base on memory manage module see mem.h
		And use disasm Module see trampoline.h.

Function List:

	public:

		Description:

			Initialization And UnInitialization Kernel Hook Engine

			- HkInitializaInlineHook	
			- HkUnInitializaInlineHook

			Create And Remove Inline Hook Information

			- HkCreateInlineHook
			- HkRemoveInlineHook

			Enable And Disable Inline Hook

			- HkEnableInlineHook
			- HkDisableInlineHook

			Lookup Inline Hook information

			--	HkLookupInlineHookEntryByHandle
			--	HkLookupInlineHookEntryByTarget

	private:

		Description:

			Allocate And Free Inline Hook Entry

		    - HkCreateInlineHookEntry
		    - HkDeleteInlineHookEntry

			Help Function Get free Handle In Table , And Arrange Table

			--  HkGetFreeInlineHookEntryHandle
			----  HkArrangeInlineHookInfoTable

			Help Function Modify System Page Protect

			-- HkUnitWriteProtectOff
			-- HkUnitWriteProtectOn

			Help Function Lock And Unlock Hook Table

			-- HkLockInlineHookTablePage
			-- HkUnLockInlineHookTablePage

			Help Function Lock And Unlock Hook Entry

			-- HkLockInlineHookEntryPage
			-- HkUnLockInlineHookEntryPage

--*/

#ifndef HOOK_HEAD
#define HOOK_HEAD

#include "pstdint.h"
#include "mem.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#pragma once

//	This is handle index of Hook Entry in hook info table 
#if defined(_M_X64) || defined(__x86_64__)
	typedef INT64 HKHANDLE;
	typedef HKHANDLE* PHKHANDLE;
	#define HK_INVALID_HANDLE_VALUE -1
#else
	typedef INT32 HKHANDLE;
	typedef HKHANDLE* PHKHANDLE;
	#define HK_INVALID_HANDLE_VALUE -1
#endif

// Hook information
typedef struct _INLINE_HOOK_ENTRY
{
	PVOID  pTarget;				// Address of the target function.
	PVOID  pDetour;				// Address of the detour function.
	PVOID  pTrampoline;			// Buffer address for the trampoline and relay function.
	UINT16 SizeOfTramPoline;	// Size of Tram Poline instruction use memory 
	UINT8  backup[64];			// Backup ordinal instruction (only 16byte sizeof(JMP_ABS))

	BOOLEAN isEnabled;			// Enabled hook

	UINT8 nIP;					// Count of the instruction boundaries.
	UINT8 oldIPs[8];			// Instruction boundaries of the target function.
	UINT8 newIPs[8];			// Instruction boundaries of the trampoline function.

	HKHANDLE Handle;			// Hook Entry in hook table index
}INLINE_HOOK_ENTRY,*PINLINE_HOOK_ENTRY;

// Hook table size
#define HOOK_TABLE_SIZE 		PAGE_SIZE

// Hook table (only level 1) can hold max number of hook entry
#define HOOK_MAX_ENTRY_NUMBER   (HOOK_TABLE_SIZE / sizeof(PVOID))

// Hook info table suport table level
#define HOOK_SUPORT_TABLE_LEVEL 1

// Hook information size
#define HOOK_HOOK_ENTRY_SIZE    sizeof(INLINE_HOOK_ENTRY)

// TrampoLine size
#define HOOK_TRAMPO_LINE_SIZE    PAGE_SIZE

// Hook table information
typedef struct _INLINE_HOOK_INFO_TABLE
{
	PMEM_BLOCK_LIST pEntryTable;	// Low table memory block
	PMEM_BLOCK_LIST*pItemsEntry;    // Item pointer of table
	UINT16          Numbers;		// Number Of Hook entry in table
	HKHANDLE        FreeEntry;		// Free entry handle
	UINT8           Level;			// Suport table level
	KIRQL			Irql;			// Irql
	KSPIN_LOCK      LookupLock;		// Table lock
	UINT32          AllocCount;		// Allocate hook entry count
	UINT32			FreeCount;		// Free hook entry count
	//PMEM_BLOCK_LIST TramPolineBlock; // Trame poline memory block
	//UINT32          BlockCount;      // Trace poline memory block use count
}INLINE_HOOK_INFO_TABLE,*PINLINE_HOOK_INFO_TABLE;

// Global Variable Hook info table
EXTERN_C INLINE_HOOK_INFO_TABLE HkInlineHookInfoTable;

// Initialize hook table information . 
// ONCE You must call this function at the beginning of your program.
BOOLEAN __fastcall HkInitializaInlineHook();

// Initialize hook table information . 
// ONCE You must call this function at the end of your program.
BOOLEAN __fastcall HkUnInitializaInlineHook();

// Create Hook for the specified target function, in disabled state.
// You must call the [HkEnableInlineHook] Enable hook. 
// Parameters:
//		pTarget		[In]	A pointer to the target function, which will be
//							overridden by the detour function.
//		pDetour		[In]	A pointer to the detour function, which will override
//							the target function.
//		ppOriginal  [Out]	A pointer to the trampoline function, which will be
//							used to call the original target function.
//		pOutHandle	[Out]	A pointer to the hook entry handle, which will be
//							used to Enable | Remove | Disable Hook.
BOOLEAN __fastcall HkCreateInlineHook(PVOID pTarget,PVOID pDetour,PVOID *ppOriginal, PHKHANDLE pOutHandle);

// Enables an already created hook.
// Parameters:
//		Handle		[In]	A handle from created hook success
//							You must first call [HkCreateInlineHook] get the handle.
BOOLEAN __fastcall HkEnableInlineHook(HKHANDLE Handle);

// Remove an created hook.
// If an hook already enable then this function will be first 
// Disable this hook and then remove this hook.
// Parameters:
//		Handle		[In]	A handle from created hook success
//							You must first call [HkCreateInlineHook] get the handle.
BOOLEAN __fastcall HkRemoveInlineHook(HKHANDLE Handle);

// Disables an already created hook.
// Parameters:
//		Handle		[In]	A handle from created hook success
//							You must first call [HkCreateInlineHook] get the handle.
BOOLEAN __fastcall HkDisableInlineHook(HKHANDLE Handle);

// Allocate new hook entry in table.
// Parameters:
//		ppNewInlineHookEntry	[Out]	A pointer to the new inline hook entry.
BOOLEAN __fastcall HkCreateInlineHookEntry(PINLINE_HOOK_ENTRY *ppNewInlineHookEntry);

// Delete hook entry in table.
// Parameters:
//		ppInlineHookEntry		[In]	Need to be delete entry pointer.
BOOLEAN __fastcall HkDeleteInlineHookEntry(PINLINE_HOOK_ENTRY ppInlineHookEntry);

// Using handle lookup table get the hook entry pointer.
// Paramenters:
//		ppNewInlineHookEntry	[Out]	A pointer to the hook entry.
//		Handle					[In]	Hook Entry Handle.
BOOLEAN __fastcall HkLookupInlineHookEntryByHandle(PINLINE_HOOK_ENTRY *ppNewInlineHookEntry, HKHANDLE Handle);

// Using target function address lookup table get the hook entry pointer.
// Paramenters:
//		ppNewInlineHookEntry	[Out]	A pointer to the hook entry.
//		pTarget					[In]	A pointer to the target function address.
BOOLEAN __fastcall HkLookupInlineHookEntryByTarget(PINLINE_HOOK_ENTRY *ppNewInlineHookEntry, PVOID pTarget);

// This unit function will be get free hook entry handle.
// Also this entry is no created.
// This is just an auxiliary function.
// Return Value:		[HKHANDLE]		Free handle				
HKHANDLE __fastcall HkGetFreeInlineHookEntryHandle();

// This unit function will be arrange hook information table.
// The table items is a array, Create holes, when they are deleted entry.
// This function can iteration table get the free handle.
BOOLEAN  __fastcall HkArrangeInlineHookInfoTable();

// Lock Hook Table Page
// Using mdl lock page
// Parameters:
//		ppMdl					[In][Out]		Mdl		
VOID HkLockInlineHookTablePage(PMDL *ppMdl);

// UnLock Hook Table Page
// Parameters:
//		pMdl					[In]	Mdl	
VOID HkUnLockInlineHookTablePage(PMDL pMdl);

// Lock Inline hook entry
// Using mdl lock page
// Parameters:
//		pEntry					[In]		Hook Entry
//		pMdl					[In][Out]	Mdl
VOID HkLockInlineHookEntryPage(PINLINE_HOOK_ENTRY pEntry,PMDL *ppMdl);

// Unlock Inline hook entry
// Parameters:
//		pMdl					[In]	Mdl
VOID HkUnLockInlineHookEntryPage(PMDL pMdl);

// This variable storage Raise Irql.
KIRQL Irql;

// This unit function will be disable page write protect.
VOID  HkUnitWriteProtectOff();

// This unit function will be enable page write protect.
VOID  HkUnitWriteProtectOn();

#endif