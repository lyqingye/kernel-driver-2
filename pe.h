
#ifndef PE_HEAD
#define PE_HEAD

#include "pe_def.h"
#include "pstdint.h"
#include "mem.h"

#pragma once

typedef struct _PE_ANALYSIS_INFO
{
	WORD    Machine;
	BOOLEAN Initialized;
	PMEM_BLOCK_LIST pFileMemBlock;

	// PE IMAGE HEADERS
	PPE_IMAGE_DOS_HEADER pDosHead;
	union 
	{
		PPE_IMAGE_NT_HEADERS32 pNtHeads32;
		PPE_IMAGE_NT_HEADERS64 pNtHeads64;
	};
	PPE_IMAGE_FILE_HEADER pFileHead;
	union 
	{
		PPE_IMAGE_OPTIONAL_HEADER32 pOptionHead32;
		PPE_IMAGE_OPTIONAL_HEADER64 pOptionHead64;
	};

	// PE IMAGE DIRECTORY
	UINT NumOfSections;
	PPE_IMAGE_SECTION_HEADER pSecHead;
	PPE_IMAGE_EXPORT_DIRECTORY pExportDirectory;
	PPE_IMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
	PPE_IMAGE_BASE_RELOCATION pRelocation;
}PE_ANALYSIS_INFO,*PPE_ANALYSIS_INFO;

// Define pe handle.
typedef PPE_ANALYSIS_INFO PEHANDLE;

// Analysis pe file from disk file buffer.
// This file block pointer to pe file buffer, No image buffer.
// Parameters:
//		pMemBlk			[In]	A pointer to the pe file memory block
//		pAnalysisInfo	[Out]	A pointer to the pe analysis information
BOOLEAN __fastcall PeAnalysisFromDiskFileBuffer(PMEM_BLOCK_LIST pMemBlk, PPE_ANALYSIS_INFO pAnalysisInfo);

// This unit function will be translation rva to foa.
// Parameters:
//		PEHANDLE		[In]	A handle to the pe file anlysis informaiton
//		Rva				[In]	Will translation virtual offset address
//		pFoa			[Out]	A pointer to the out put file offset address
BOOLEAN __fastcall PeUnitRvaToFoa(PEHANDLE Handle, UINT Rva,PUINT pFoa);

// define Enumeration Of Section Routine.
// If return value equal FALSE, then stop enum.
// Parameters:
//		pSectionInfo	[Out]	A pointer will be section information.
//		Index			[Out]	Index of sections.
typedef BOOLEAN(*PENUM_SECTION_ROUTINE)(PPE_IMAGE_SECTION_HEADER pSectionInfo, UINT Index, PVOID Parameter);

// This function will be enumeratiom of section.
// Parameters:
//		Handle			[In]	A handle to the pe file anlysis informaiton.
//		pEnumRoutine	[In]	A pointer to the enumeration routine.
BOOLEAN __fastcall PeEnumSection(PEHANDLE Handle, PVOID Parameter,PENUM_SECTION_ROUTINE pEnumRoutine);

// Define Enumeration Of Export Function Information
typedef struct _PE_ENUM_EXPORT_INFO {
	PWORD  pIndexRva;	// Pointer to the Function ordinal rva
	PUINT  pFuncAddrRva;// Pointer to the Function rva	
	PUINT  pNameRva;	// Pointer to the Function name rva
	struct _ExtraInfo {
		PCHAR pName; // Pointer to the Function Name
		PVOID Parameter;//Option Parameter
	}ExtraInfo;
}PE_ENUM_EXPORT_INFO, *PPE_ENUM_EXPORT_INFO;

// Define Enumeration Of Export table routine.
// If return value equal FALSE, then stop enum.
// Parameters:
//		pExpInfo		[Out]	A pointer to the export function infomation.
typedef BOOLEAN(*PENUM_EXPORT_ROUTINE)(PPE_ENUM_EXPORT_INFO pExpInfo);

// This function will be enumeration for export table.
// Parameters:
//		Handle			[In]	A handle to the pe file anlysis informaiton.
//		pEnumRoutine	[In]	A pointer to the enumeration routine.
BOOLEAN __fastcall PeEnumExportTable(PEHANDLE Handle, PVOID Parameter, PENUM_EXPORT_ROUTINE pEnumRoutine);

// Define Enumeration Of Import Funciton Information
typedef struct _PE_ENUM_IMPORT_INFO {
	UINT  DllIndex;		// Index of dll	
	WORD  Hit;			// hit 
	PUINT pThunk;		// Pointer to the thunk 
	PUINT pIat;			// Pointer to the iat thunk 
	PUINT pFuncNameRva;	// Pointer to the function name rva
	PPE_IMAGE_IMPORT_DESCRIPTOR pDllInfo;
	struct{
		PCHAR pDllName;	// Pointer to the dll name
		PCHAR pFuncName;// Pointer to the function name
		PVOID Parameter;//Option Parameter
	}ExtraInfo;
}PE_ENUM_IMPORT_INFO,*PPE_ENUM_IMPORT_INFO;

// Define Enumeration Of Import table routine.
// If return value equal FALSE, then stop enum.
// Parameters:
//		pIptInfo		[Out]	A pointer to the import table information.
typedef BOOLEAN(*PENUM_IMPORT_ROUTINE)(PPE_ENUM_IMPORT_INFO pIptInfo);

// This function will be enumeration for import table.
// Parameters:
//		Handle			[In]	A handle to the pe file anlysis informaiton.
//		pEnumRoutine	[In]	A pointer to the enumeration routine.
BOOLEAN __fastcall PeEnumImportTable(PEHANDLE Handle, PVOID Parameter, PENUM_IMPORT_ROUTINE pEnumRoutine);

// Define Enumeration Of Base Relocation Information.
typedef struct _PE_ENUM_RELOCATION_INFO {
	UINT RelIndex;		// Relcation block index
	PWORD pItem;		// Pointer to the block item
	PPE_IMAGE_BASE_RELOCATION pRelocation; // Pointer to the block information
	struct{
		WORD Type;		// Relocation type
		UINT Rva;		// Relocation virtual address offset
		PVOID Fa;		// Relocation file buffer address
		PVOID Parameter;//Option Parameter
	}ExtraInfo;
}PE_ENUM_RELOCATION_INFO,*PPE_ENUM_RELOCOATION_INFO;

// Define Enumeration Of Relocation table routine.
// If return value equal FALSE, then stop enum.
// Parameters:
//		pRelInfo		[Out]	A pointer to the relocation information.
typedef BOOLEAN(*PENUM_RELOCATION_ROUTINE)(PPE_ENUM_RELOCOATION_INFO pRelInfo);

// This function will be enumeration for relocation table.
// Parameters:
//		Handle			[In]	A handle to the pe file anlysis informaiton.
//		pEnumRoutine	[In]	A pointer to the enumeration routine.
BOOLEAN __fastcall PeEnumRelocationTable(PEHANDLE Handle, PVOID Parameter, PENUM_RELOCATION_ROUTINE pEnumRoutine);

#endif