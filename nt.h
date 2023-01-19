
#define _DBG

#ifndef NT_HEAD
#define NT_HEAD

#include "nt_def.h"
#include "mem.h"
#include "symbol_map.h"

// disable Use the discarded function 
#pragma warning(disable:4996) 

#pragma once

// Define Kernel Struct Informations
typedef struct _NT_STRUCT_INFORMATIONS{
	PSYMBOL_MAP_ITEM_INFO Struct_Header_OBJECT_HEADER;
	INT16 Offset_TypeIndex_OBJECT_HEADER;
	INT16 Offset_InfoMask_OBJECT_HEADER;
	PSYMBOL_MAP_ITEM_INFO Struct_Header_EPROCESS;
	INT16 Offset_ActiveProcessLinks_EPROCESS;
	INT16 Offset_UniqueProcessId_EPROCESS;
	INT16 Offset_SeAuditProcessCreationInfo_EPROCESS;
	INT16 Offset_ImageFileName_EPROCESS;
	INT16 Offset_VirtualSize_EPROCESS;
}NT_STRUCT_INFORMATIONS,*PNT_STRUCT_INFORMATIONS;

EXTERN_C NT_STRUCT_INFORMATIONS NtStructInformations;

// Define Nt information
typedef struct _NT_INFORMATIONS{
	BOOLEAN Initialized;// Is initialize
	PVOID KernelBase;	// Kernel module base
	PSYMBOL_MAP_HEAD_INFO NtSymbolMapHead; // Nt symbol map header

	// Undocument variable
	PKDDEBUGGER_DATA64 pKdDebuggerDataBlock;
	PERESOURCE	pPsLoadedModuleResource;
	PKGUARDED_MUTEX pPspActiveProcessMutex; // Winxp
	PEX_PUSH_LOCK pPspActiveProcessLock; // Win10
	PVOID ObTypeIndexTable;
	PINT8 pObHeaderCookie;
	PINT8 pObpInfoMaskToOffset;

	// Undocument function
	PSPCREATEPROCESS PspCreateProcess;
	NTCREATEPROCESS NtCreateProcess;
	NTCREATEPROCESSEX NtCreateProcessEx;
	NTCREATEUSERPROCESS NtCreateUserProcess;
	NTCREATEFILE NtCreateFile;
	NTSHUTDOWNSYSTEM NtShutdownSystem;
	
}NT_INFORMATIONS, *PNT_INFORMATIONS;

// Nt information struct variable
EXTERN_C NT_INFORMATIONS NtInformations;

// IO Dispatch Routine
// Initialize Symbols table routine
// Parameters:
//		pHead			[In]	Dispatch header	
VOID NtExInitializeSymbolsTable(PIO_DISPATCH_HEADER pHead);

// Initialization Nt library
// Parameters:
//		None.
BOOLEAN NtExInitialization();

// UnInitialization Nt library
// Parameters:
//		None.
BOOLEAN NtExUnInitialization();

// Initialization some Undocument variable and function
// Parameters:
//		None.
BOOLEAN NtExInitializeUnDocumentInformation();

// Initialization some struct information   
// Parameters:
//		None.
BOOLEAN NtExInitializeStructInformations();

// Get symbols address
// Parameters:
//		pName			[In]	Symbols Name
//		fixOffset		[In]	fixOffset = SymbolsImageBase - KernelImageBase
// Return Value:
//		NULL
//		NOT NULL	
PVOID NtExGetSymbolsAddress(const PCHAR pName,DWORD64 fixOffset);

// Get struct symbols header
// Parameters:
//		pName			[In]	struct Name
// Return Value:
//		NULL
//		NOT NULL
PSYMBOL_MAP_ITEM_INFO NtExGetSymbolsStructHead(const PCHAR pName);

// Get struct child information by use struct head
// Parameters:
//		pHead			[In]	struct Header
//      pChildName		[In]	child Name
// Return Value:
//		NULL
//		NOT NULL
PSYMBOL_MAP_ITEM_INFO NtExGetStructChildInfoByHead(PSYMBOL_MAP_ITEM_INFO pHead,const PCHAR pChildName);

// Get struct child information
// Parameters:
//		pStructName		[In]	struct Name
//		pChildName		[In]	Child Name
// Return Value:
//		NULL
//		NOT NULL
PSYMBOL_MAP_ITEM_INFO NtExGetStructChildInfo(const PCHAR pStructName,const PCHAR pChildName);

// This function get the first PCR
// Parameters:
//		None.
PVOID NtExGetFirstKpcr();

// Get kernel base from ZwQuerySystemInformation is UnDocument Function
// And This UnDocument get the module information from PsLoadedModuleList
// Parameters:
//		None.
// Return Value:
//		This function will be get the kernel base in normal
//		If return NULL , This function maybe hooked 
//		If return NOT NULL , This value maybe is reload kernel address(Do not exclude this possibility).
PVOID NtExGetKernelBaseFromUnDocumentFunction();

// Get kernel base from DRIVER_OBJECT 
// Parameters:
//		pDriverObject 		[In]	Driver Object
PVOID NtExGetKernelBaseFromDriverObject(PDRIVER_OBJECT pDriverObject);

// Get kernel module base from DRIVER_OBJECT
// Parameters:
//		pDriverObject 		[In]	Driver Object
//		pModuleName			[In]	Module Name
PVOID NtExGetModuleBaseFromDriverObject(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pModuleName);

// Get Kernel module base from PsLoadedModuleList
// This function use the ExAcquireResourceExclusiveLite so is safe 
// Parameters:
//		pName				[In]	ModuleName
PVOID NtExGetModuleBaseFromModuleList(PUNICODE_STRING pName);

// Snap system process information from PsActiveProcessHead
// This function use the ExAcquireResourceExclusiveLite so is safe
// Parameters:
//		ProcessInfo			[In]		Process information buffer
//										if NULL this function will be out total the process buffer length
//		InfoLength			[In]		Input buffer length
//		OutLength			[In][Out]	Out the process information total length		
NTSTATUS NtExSnapProcessInformation(PVOID ProcessInfo,ULONG InfoLength,PULONG OutLength);

// Get EPROCESS Image File Name
// Parameters:
//		pEprocess			[In]		Eprocess
//		pImageFileName		[In][Out]	Out of Image file name , you must be free this string		
BOOLEAN NtExGetProcessFileName(PEPROCESS pEprocess,PUNICODE_STRING pImageFileName);

// Get EPROCESS Image File Name By Process Handle
// Parameters:
//		ProcessHandle		[In]		Process Handle
//		pImageFileName		[In][Out]	Out of Image file name , you must be free this string				
BOOLEAN NtExGetProcessFileNameByHandle(HANDLE ProcessHandle,PUNICODE_STRING pImageFileName);

// Get Object Type
// Parameters:
//		Object				[In]		Object
// Return Value:
//		TypeObject
PVOID NtExGetObjectType(PVOID Object);

// Get Object Name
// Parameters:
// Return Value:	
// 		POBJECT_HEADER_NAME_INFO
POBJECT_HEADER_NAME_INFO NtExGetObjectNameInfo(PVOID Object);

// Test
VOID NtEnumParseRootDirectory();

#endif