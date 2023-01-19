#include <ntddk.h>
#include <windef.h>
#include "unit.h"
#include "io_dispatch.h"
#include "filter.h"

// Define Kernel Name
#define	DEVICE_NAME			L"\\Device\\ClrKIH64"
#define LINK_NAME			L"\\DosDevices\\ClrKIH64"
#define LINK_GLOBAL_NAME	L"\\DosDevices\\Global\\ClrKIH64"

//
// Driver Entry
//
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString);

//
// Driver Unload
//
VOID DriverUnload(PDRIVER_OBJECT pDriverObj);

//
// Dispatch Create
// 
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp);

//
// Dispatch Close
// 
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp);

//
// Dispatch Io control
//
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp);

// Alloc Text routine
#pragma alloc_text(INT,DriverEntry)
#pragma alloc_text (PAGED,DriverUnload)
#pragma alloc_text (PAGED,DispatchCreate)
#pragma alloc_text (PAGED,DispatchClose)
#pragma alloc_text (PAGED,DispatchIoctl)

VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;

	PAGED_CODE();

	// Delete symbol link
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);

	// Delete Device
	IoDeleteDevice(pDriverObj->DeviceObject);

	// Release someting
	UnInitializationUnit();
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PAGED_CODE();

	// Set irp status
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	// Complete irp
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	// return
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	PAGED_CODE();

	// Set irp status
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	// Complete irp
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	// return
	return STATUS_SUCCESS;
}

#define CTL_CODE_COMMUNICATE  CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG uInSize;
	PIO_STACK_LOCATION pIrpStack;
	PIO_DISPATCH_HEADER pDispatchHeader;

	PAGED_CODE();

	// Get irp stack
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	// Set dispatch header pointer
	pDispatchHeader = pIrp->AssociatedIrp.SystemBuffer;

	// Get Input buffer size
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;

	/*
		Communicate struct:
			[IO_DISPATCH_HEADER] [IO_DISPATCH_BODY] [Data]

		IO_DISPATCH_BODY.InBuffLen = sizeof(IO_DISPATCH_HEADER) + sizeof(IO_DISPATCH_BODY) + sizeof(Data)

	*/
	if (MmIsAddressValid((PVOID)pDispatchHeader))
	{
		if (uInSize == pDispatchHeader->Body.InBuffLen)
		{
			if (uInSize >= sizeof(IO_DISPATCH_HEADER))
			{
				// Switch control code 
				switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
				{
					case CTL_CODE_COMMUNICATE:
					{
						// Call dispatch routine
						if (IoDispatchCallRoutine(pDispatchHeader))
						 {
							// if out put information
							if (pDispatchHeader->Body.OutBuffLen > 0)
							{
								// Set out buffer information
								pIrp->AssociatedIrp.SystemBuffer = pDispatchHeader->Body.OutBuff;
								pIrp->IoStatus.Information = pDispatchHeader->Body.OutBuffLen;
								pIrp->IoStatus.Status = pDispatchHeader->Body.Status;
								break;
							 }
							else
							{
								pIrp->IoStatus.Information = pDispatchHeader->Body.OutBuffLen = 0;
								pIrp->IoStatus.Status = pDispatchHeader->Body.Status;
								break;
							}
						 }
						 else
						 {
								pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
								break;
						 }
						break;
					}
					default:
					{
							   pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
							   break;
					}
				}
			}
			else
			{
				pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				
			}
		}
		else
		{
			pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		}
	}
	else
	{
		pIrp->IoStatus.Status = STATUS_INVALID_PARAMETER;
	}
	
	// Complete irp
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	// return status
	return status;
}


typedef NTSTATUS(*NTCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
typedef NTSTATUS(*NTTERMINATEPROCESS)(HANDLE, NTSTATUS);

NTCREATEPROCESS Old_NtCreateProcess;
NTTERMINATEPROCESS Old_NtTerminateProcess;

NTSTATUS
NTAPI
Fake_NtTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus
)
{

	PEPROCESS pEprocess=0;
	NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, GENERIC_ALL, *PsProcessType, KernelMode, &pEprocess, NULL);
	if (NT_SUCCESS(status))
	{
		
		PUNICODE_STRING FileName = (PUNICODE_STRING)(*(ULONG64*)(((PUCHAR)pEprocess) + 0x468));
		if (wcsstr(FileName->Buffer, L"explorer") != NULL)
		{
			PEPROCESS self = PsGetCurrentProcess();
			DbgPrint("%wZ \n", (PUNICODE_STRING)(*(ULONG64*)(((PUCHAR)self) + 0x468)));
			ObDereferenceObject(pEprocess);
			return STATUS_INVALID_HANDLE;
		}
		ObDereferenceObject(pEprocess);
	}
	return Old_NtTerminateProcess(ProcessHandle, ExitStatus);
}



NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	PDEVICE_OBJECT pDevObj;

	// Set major function
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

	// Set driver unload routine
	pDriverObj->DriverUnload = DriverUnload;

	// Create device
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 
							0,
							&ustrDevName,
							FILE_DEVICE_UNKNOWN,
							0, 
							FALSE, 
							&pDevObj);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	// Create symbol link
	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);

	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		// Create faild , delete device
		IoDeleteDevice(pDevObj);
		return status;
	}

	// Test

	// Initalization Unit librarys
	InitializationUnit();

	// Add Io control routine
	IoDispatchInsertRoutine(NtExInitializeSymbolsTable, 0);
	IoDispatchInsertRoutine(FtInitializationHook,2);
	return STATUS_SUCCESS;
}
