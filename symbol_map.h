
#ifndef SYMBOL_MAP_HEAD
#define SYMBOL_MAP_HEAD

#pragma warning(disable:4117) 
#pragma warning(disable:4996) 

#define _KERNEL_MODE
#ifdef _KERNEL_MODE
#include <ntddk.h>
#include "io_dispatch.h"
#else
#include "dbg_help.h"
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 0X1000
#endif
#pragma once

// Define symbol info
typedef struct _SYMBOL_INFO
{
	ULONG       SizeOfStruct;
	ULONG       TypeIndex;
	ULONG64     Reserved[2];
	ULONG       Index;
	ULONG       Size;
	ULONG64     ModBase;
	ULONG       Flags;
	ULONG64     Value;
	ULONG64     Address;
	ULONG       Register;
	ULONG       Scope;
	ULONG       Tag;
	ULONG       NameLen;
	ULONG       MaxNameLen;
	CHAR        Name[1];
} SYMBOL_INFO, *PSYMBOL_INFO;

#pragma pack(push, 1)
// Define symbol map header information
typedef struct _SYMBOL_MAP_HEAD_INFO{
	struct _IO_DISPATCH_HEADER DispatchHead; // This struct is a dispatch header
	DWORD32 NumberOfItem;	// Number Of item see struct SYMBOL_MAP_ITEM_INFO 
	DWORD32 SizeOfHeader;	// Size of Header 
	DWORD32 MemoryUsege;	// Memory use count
	DWORD32 MemorySize;		// Allocated memory size
	DWORD32 OffsetOfItemArray;	// Item array offset of symbol map header
	DWORD32 OffsetOfNextItem;	// Next free item offset of symbol map header
	PVOID ImageBase;		// Image base
}SYMBOL_MAP_HEAD_INFO, *PSYMBOL_MAP_HEAD_INFO;

// Define symbol map item information
typedef struct _SYMBOL_MAP_ITEM_INFO{
	CHAR    NamePadding;// Last Item Name Padding
	USHORT  Type;		// Type Or Symbols....
	DWORD32 Flags;		// Symbol flags
	union 
	{
		DWORD64 Address;// Symbol address
		DWORD64 Offset;	// Type offset
	};
	DWORD32 ChildCount; // Struct Child Count
	DWORD32 NameLen;	// Symbol name length
	DWORD32 TypeLength; // Data Type length
	DWORD32 SizeOfType; // Type size
	DWORD32 SizeOfItem;	// Item size
	DWORD32 NameOffset;	// Symbol name offset of item
}SYMBOL_MAP_ITEM_INFO, *PSYMBOL_MAP_ITEM_INFO;

#pragma pack(pop)

// Allocate symbols map 
// Parameters:
//		ppSymMapHead		[In]	A pointer to the symbol map header pointer
BOOLEAN SymMapAllocateMap(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead);

// Free symbols map
// Parameters:
//		pSymMapHead			[In]	A pointer to the symblo map header
BOOLEAN SymMapFreeMap(PSYMBOL_MAP_HEAD_INFO pSymMapHead);

// This function can extend the symbol map,that if memory page Exhausted 
// If memory page Exhausted then allocate new pool , pool size, on the basis of an increase PAGE_SIZE
// And copy ordinal data to new pool And free old pool
// Parameters:
//		ppSymMapHead		[In]	A pointer to the symbol map header pointer
BOOLEAN SymMapExtendMap(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead);

// Get symbol name from item
// Parameters:
//		ppItem				[In]	A pointer to the symbol map item 
// Return Value:
//		NULL		Faild Please check parameters valid
//		NOT NULL			
PCHAR SymMapGetItemName(PSYMBOL_MAP_ITEM_INFO *ppItem);

// Get symbol map item array
// Parameters:
//		ppSymMapHead		[In]	A pointer to the symbol map header pointer
// Return Value:
//		NULL		Faild Please check parameters valid
//		NOT NULL	
PVOID SymMapGetItemArray(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead);

// Net symbol map next free item address
// Parameters:
//		ppSymMapHead		[In]	A pointer to the symbol map header pointer
// Return Value:
//		NULL		Faild Please check parameters valid
//		NOT NULL
PVOID SymMapGetNextItem(PSYMBOL_MAP_HEAD_INFO *ppSymMapHead);

// Insert symbol to map 
// Symbol source from SYMBOL_INFO see the symbols enumeration routine
// Parameters:
//		ppSymMap			[In]	A pointer to the symbol map header pointer
//		pSymbol				[In]	A pointer to the symbol information see PSYMBOL_INFO source form symbols enumeration routine
//		OutItem				[Out]	A pointer to the out of insert item  OPTION you can set this NULL
BOOLEAN SymMapInsertSymbol(PSYMBOL_MAP_HEAD_INFO *ppSymMap,PSYMBOL_INFO pSymbol, PSYMBOL_MAP_ITEM_INFO *OutItem);

// Lookup symbol map get the symbols item
// Parameters:
//		ppSymMap			[In]	A pointer to the symbol map header pointer
//		Name				[In]	A pointet to the symbol name
//		ppOutSymbol			[Out]	A pointer to the lookup symbol information
#ifdef _KERNEL_MODE
BOOLEAN SymMapLookupSymbol(PSYMBOL_MAP_HEAD_INFO *ppSymMap, PANSI_STRING Name, PSYMBOL_MAP_ITEM_INFO *ppOutSymbol);
#else
BOOLEAN SymMapLookupSymbol(PSYMBOL_MAP_HEAD_INFO *ppSymMap, PCHAR Name, PSYMBOL_MAP_ITEM_INFO *ppOutSymbol);
#endif

#endif