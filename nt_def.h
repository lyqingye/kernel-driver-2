
#ifndef NT_DEF_HEAD
#define NT_DEF_HEAD

#include "pstdint.h"

#pragma once
#pragma warning(disable : 4214)

typedef struct _DBGKD_DEBUG_DATA_HEADER64
{

	//
	// Link to other blocks
	//

	LIST_ENTRY64 List;

	//
	// This is a unique tag to identify the owner of the block.
	// If your component only uses one pool tag, use it for this, too.
	//

	ULONG OwnerTag;

	//
	// This must be initialized to the size of the data block,
	// including this structure.
	//

	ULONG Size;

} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64
{

	DBGKD_DEBUG_DATA_HEADER64 Header;

	//
	// Base address of kernel image
	//

	ULONG64 KernBase;

	//
	// DbgBreakPointWithStatus is a function which takes an argument
	// and hits a breakpoint.  This field contains the address of the
	// breakpoint instruction.  When the debugger sees a breakpoint
	// at this address, it may retrieve the argument from the first
	// argument register, or on x86 the eax register.
	//

	ULONG64 BreakpointWithStatus; // address of breakpoint

	//
	// Address of the saved context record during a bugcheck
	//
	// N.B. This is an automatic in KeBugcheckEx's frame, and
	// is only valid after a bugcheck.
	//

	ULONG64 SavedContext;

	//
	// help for walking stacks with user callbacks:
	//

	//
	// The address of the thread structure is provided in the
	// WAIT_STATE_CHANGE packet.  This is the offset from the base of
	// the thread structure to the pointer to the kernel stack frame
	// for the currently active usermode callback.
	//

	USHORT ThCallbackStack; // offset in thread data

	//
	// these values are offsets into that frame:
	//

	USHORT NextCallback; // saved pointer to next callback frame
	USHORT FramePointer; // saved frame pointer

	//
	// pad to a quad boundary
	//
	USHORT PaeEnabled : 1;

	//
	// Address of the kernel callout routine.
	//

	ULONG64 KiCallUserMode; // kernel routine

	//
	// Address of the usermode entry point for callbacks.
	//

	ULONG64 KeUserCallbackDispatcher; // address in ntdll

	//
	// Addresses of various kernel data structures and lists
	// that are of interest to the kernel debugger.
	//

	ULONG64 PsLoadedModuleList;
	ULONG64 PsActiveProcessHead;
	ULONG64 PspCidTable;

	ULONG64 ExpSystemResourcesList;
	ULONG64 ExpPagedPoolDescriptor;
	ULONG64 ExpNumberOfPagedPools;

	ULONG64 KeTimeIncrement;
	ULONG64 KeBugCheckCallbackListHead;
	ULONG64 KiBugcheckData;

	ULONG64 IopErrorLogListHead;

	ULONG64 ObpRootDirectoryObject;
	ULONG64 ObpTypeObjectType;

	ULONG64 MmSystemCacheStart;
	ULONG64 MmSystemCacheEnd;
	ULONG64 MmSystemCacheWs;

	ULONG64 MmPfnDatabase;
	ULONG64 MmSystemPtesStart;
	ULONG64 MmSystemPtesEnd;
	ULONG64 MmSubsectionBase;
	ULONG64 MmNumberOfPagingFiles;

	ULONG64 MmLowestPhysicalPage;
	ULONG64 MmHighestPhysicalPage;
	ULONG64 MmNumberOfPhysicalPages;

	ULONG64 MmMaximumNonPagedPoolInBytes;
	ULONG64 MmNonPagedSystemStart;
	ULONG64 MmNonPagedPoolStart;
	ULONG64 MmNonPagedPoolEnd;

	ULONG64 MmPagedPoolStart;
	ULONG64 MmPagedPoolEnd;
	ULONG64 MmPagedPoolInformation;
	ULONG64 MmPageSize;

	ULONG64 MmSizeOfPagedPoolInBytes;

	ULONG64 MmTotalCommitLimit;
	ULONG64 MmTotalCommittedPages;
	ULONG64 MmSharedCommit;
	ULONG64 MmDriverCommit;
	ULONG64 MmProcessCommit;
	ULONG64 MmPagedPoolCommit;
	ULONG64 MmExtendedCommit;

	ULONG64 MmZeroedPageListHead;
	ULONG64 MmFreePageListHead;
	ULONG64 MmStandbyPageListHead;
	ULONG64 MmModifiedPageListHead;
	ULONG64 MmModifiedNoWritePageListHead;
	ULONG64 MmAvailablePages;
	ULONG64 MmResidentAvailablePages;

	ULONG64 PoolTrackTable;
	ULONG64 NonPagedPoolDescriptor;

	ULONG64 MmHighestUserAddress;
	ULONG64 MmSystemRangeStart;
	ULONG64 MmUserProbeAddress;

	ULONG64 KdPrintCircularBuffer;
	ULONG64 KdPrintCircularBufferEnd;
	ULONG64 KdPrintWritePointer;
	ULONG64 KdPrintRolloverCount;

	ULONG64 MmLoadedUserImageList;

	// NT 5.1 Addition

	ULONG64 NtBuildLab;
	ULONG64 KiNormalSystemCall;

	// NT 5.0 hotfix addition

	ULONG64 KiProcessorBlock;
	ULONG64 MmUnloadedDrivers;
	ULONG64 MmLastUnloadedDriver;
	ULONG64 MmTriageActionTaken;
	ULONG64 MmSpecialPoolTag;
	ULONG64 KernelVerifier;
	ULONG64 MmVerifierData;
	ULONG64 MmAllocatedNonPagedPool;
	ULONG64 MmPeakCommitment;
	ULONG64 MmTotalCommitLimitMaximum;
	ULONG64 CmNtCSDVersion;

	// NT 5.1 Addition

	ULONG64 MmPhysicalMemoryBlock;
	ULONG64 MmSessionBase;
	ULONG64 MmSessionSize;
	ULONG64 MmSystemParentTablePage;

	// Server 2003 addition

	ULONG64 MmVirtualTranslationBase;

	USHORT OffsetKThreadNextProcessor;
	USHORT OffsetKThreadTeb;
	USHORT OffsetKThreadKernelStack;
	USHORT OffsetKThreadInitialStack;

	USHORT OffsetKThreadApcProcess;
	USHORT OffsetKThreadState;
	USHORT OffsetKThreadBStore;
	USHORT OffsetKThreadBStoreLimit;

	USHORT SizeEProcess;
	USHORT OffsetEprocessPeb;
	USHORT OffsetEprocessParentCID;
	USHORT OffsetEprocessDirectoryTableBase;

	USHORT SizePrcb;
	USHORT OffsetPrcbDpcRoutine;
	USHORT OffsetPrcbCurrentThread;
	USHORT OffsetPrcbMhz;

	USHORT OffsetPrcbCpuType;
	USHORT OffsetPrcbVendorString;
	USHORT OffsetPrcbProcStateContext;
	USHORT OffsetPrcbNumber;

	USHORT SizeEThread;

	ULONG64 KdPrintCircularBufferPtr;
	ULONG64 KdPrintBufferSize;

	ULONG64 KeLoaderBlock;

	USHORT SizePcr;
	USHORT OffsetPcrSelfPcr;
	USHORT OffsetPcrCurrentPrcb;
	USHORT OffsetPcrContainedPrcb;

	USHORT OffsetPcrInitialBStore;
	USHORT OffsetPcrBStoreLimit;
	USHORT OffsetPcrInitialStack;
	USHORT OffsetPcrStackLimit;

	USHORT OffsetPrcbPcrPage;
	USHORT OffsetPrcbProcStateSpecialReg;
	USHORT GdtR0Code;
	USHORT GdtR0Data;

	USHORT GdtR0Pcr;
	USHORT GdtR3Code;
	USHORT GdtR3Data;
	USHORT GdtR3Teb;

	USHORT GdtLdt;
	USHORT GdtTss;
	USHORT Gdt64R3CmCode;
	USHORT Gdt64R3CmTeb;

	ULONG64 IopNumTriageDumpDataBlocks;
	ULONG64 IopTriageDumpDataBlocks;

	// Longhorn addition

	ULONG64 VfCrashDataBlock;
	ULONG64 MmBadPagesDetected;
	ULONG64 MmZeroedPageSingleBitErrorsDetected;

	// Windows 7 addition

	ULONG64 EtwpDebuggerData;
	USHORT OffsetPrcbContext;

	// Windows 8 addition

	USHORT OffsetPrcbMaxBreakpoints;
	USHORT OffsetPrcbMaxWatchpoints;

	ULONG OffsetKThreadStackLimit;
	ULONG OffsetKThreadStackBase;
	ULONG OffsetKThreadQueueListEntry;
	ULONG OffsetEThreadIrpList;

	USHORT OffsetPrcbIdleThread;
	USHORT OffsetPrcbNormalDpcState;
	USHORT OffsetPrcbDpcStack;
	USHORT OffsetPrcbIsrStack;

	USHORT SizeKDPC_STACK_FRAME;

	// Windows 8.1 Addition

	USHORT OffsetKPriQueueThreadListHead;
	USHORT OffsetKThreadWaitReason;

	// Windows 10 RS1 Addition

	USHORT Padding;
	ULONG64 PteBase;

} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG Unknow1;
	ULONG Unknow2;
#ifdef _WIN64
	ULONG Unknow3;
	ULONG Unknow4;
#endif
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	PEPROCESS pEprocess;
	HANDLE UniqueProcessId;
	UNICODE_STRING ImageName;
	SIZE_T VirtualSize;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _EX_PUSH_LOCK
{

//
// LOCK bit is set for both exclusive and shared acquires
//
#define EX_PUSH_LOCK_LOCK_V ((ULONG_PTR)0x0)
#define EX_PUSH_LOCK_LOCK ((ULONG_PTR)0x1)

//
// Waiting bit designates that the pointer has chained waiters
//

#define EX_PUSH_LOCK_WAITING ((ULONG_PTR)0x2)

//
// Waking bit designates that we are either traversing the list
// to wake threads or optimizing the list
//

#define EX_PUSH_LOCK_WAKING ((ULONG_PTR)0x4)

//
// Set if the lock is held shared by multiple owners and there are waiters
//

#define EX_PUSH_LOCK_MULTIPLE_SHARED ((ULONG_PTR)0x8)

//
// Total shared Acquires are incremented using this
//
#define EX_PUSH_LOCK_SHARE_INC ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS ((ULONG_PTR)0xf)

	union {
		struct
		{
			ULONG_PTR Locked : 1;
			ULONG_PTR Waiting : 1;
			ULONG_PTR Waking : 1;
			ULONG_PTR MultipleShared : 1;
			ULONG_PTR Shared : sizeof(ULONG_PTR) * 8 - 4;
		};
		ULONG_PTR Value;
		PVOID Ptr;
	};
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
{
	ULONG Attribute;
	SIZE_T Size;
	ULONG_PTR Value;
	ULONG Unknown;
} PROC_THREAD_ATTRIBUTE_ENTRY, *PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
{
	ULONG Length;
	PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	USHORT Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef enum _SHUTDOWN_ACTION{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
}SHUTDOWN_ACTION;

typedef struct _OBJECT_DIRECTORY_ENTRY {
    struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY {
    struct _OBJECT_DIRECTORY_ENTRY *HashBuckets[37];
    EX_PUSH_LOCK Lock;
    struct _DEVICE_MAP *DeviceMap;
} OBJECT_DIRECTORY, *POBJECT_DIRECTORY;

typedef struct _DEVICE_MAP {
    POBJECT_DIRECTORY DosDevicesDirectory;
    POBJECT_DIRECTORY GlobalDosDevicesDirectory;
}DEVICE_MAP,*PDEVICE_MAP;

typedef struct _OBJECT_HEADER_NAME_INFO {
    POBJECT_DIRECTORY Directory;
    UNICODE_STRING Name;
    ULONG QueryReferences;
#ifdef _WIN64
    ULONG64  Reserved3;   // Win64 requires these structures to be 16 byte aligned.
#endif
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;


NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN ULONG SystemInformationClass,
												 IN OUT PVOID SystemInformation,
												 IN ULONG SystemInformationLength,
												 OUT PULONG ReturnLength);

NTSYSAPI VOID __fastcall ExfAcquirePushLockShared(PEX_PUSH_LOCK PushLock);

NTSYSAPI VOID __fastcall ExfReleasePushLockShared(PEX_PUSH_LOCK PushLock);

typedef NTSTATUS (*PSPCREATEPROCESS)(OUT PHANDLE ProcessHandle,
									 IN ACCESS_MASK DesiredAccess,
									 IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
									 IN HANDLE ParentProcess OPTIONAL,
									 IN ULONG Flags,
									 IN HANDLE SectionHandle OPTIONAL,
									 IN HANDLE DebugPort OPTIONAL,
									 IN HANDLE ExceptionPort OPTIONAL,
									 IN ULONG JobMemberLevel);

typedef NTSTATUS (*NTCREATEPROCESS)(__out PHANDLE ProcessHandle,
									__in ACCESS_MASK DesiredAccess,
									__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
									__in HANDLE ParentProcess,
									__in BOOLEAN InheritObjectTable,
									__in_opt HANDLE SectionHandle,
									__in_opt HANDLE DebugPort,
									__in_opt HANDLE ExceptionPort);

typedef NTSTATUS (*NTCREATEPROCESSEX)(__out PHANDLE ProcessHandle,
									  __in ACCESS_MASK DesiredAccess,
									  __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
									  __in HANDLE ParentProcess,
									  __in ULONG Flags,
									  __in_opt HANDLE SectionHandle,
									  __in_opt HANDLE DebugPort,
									  __in_opt HANDLE ExceptionPort,
									  __in ULONG JobMemberLevel);

typedef NTSTATUS(*NTCREATEUSERPROCESS)(OUT PHANDLE ProcessHandle,
									  OUT PHANDLE ThreadHandle,
									  IN ACCESS_MASK ProcessDesiredAccess,
									  IN ACCESS_MASK ThreadDesiredAccess,
									  IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
									  IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
									  IN ULONG CreateProcessFlags,
									  IN ULONG CreateThreadFlags,
									  IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
									  IN PVOID Parameter9,
									  IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList);

typedef NTSTATUS (*NTCREATEFILE)(__out PHANDLE FileHandle,
								 __in ACCESS_MASK DesiredAccess,
								 __in POBJECT_ATTRIBUTES ObjectAttributes,
								 __out PIO_STATUS_BLOCK IoStatusBlock,
								 __in_opt PLARGE_INTEGER AllocationSize,
								 __in ULONG FileAttributes,
								 __in ULONG ShareAccess,
								 __in ULONG CreateDisposition,
								 __in ULONG CreateOptions,
								 __in PVOID EaBuffer,
								 __in ULONG EaLength);

typedef NTSTATUS(*NTSHUTDOWNSYSTEM)(SHUTDOWN_ACTION Parameters);


#endif