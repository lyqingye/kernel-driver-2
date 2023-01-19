
#include "filter.h"

// Import Nt infotmations 
NT_INFORMATIONS NtInformations;

// Hook function
HKHANDLE HkHandlePspCreateProcess = 0;
PSPCREATEPROCESS Old_PspCreateProcess = NULL;

HKHANDLE HkHandleNtCreateProcess = 0;
NTCREATEPROCESS Old_NtCreateProcess = NULL;

HKHANDLE HkHandleNtCreateProcessEx = 0;
NTCREATEPROCESSEX Old_NtCreateProcessEx = NULL;

HKHANDLE HkHandleNtCreateUserProcess = 0;
NTCREATEUSERPROCESS Old_NtCreateUserProcess = NULL;

HKHANDLE HkHandleNtCreateFile = 0;
NTCREATEFILE Old_NtCreateFile = NULL;

HKHANDLE HkHandleNtShutdownSystem = 0;
NTSHUTDOWNSYSTEM Old_NtShutdownSystem = NULL;

VOID FtInitializationHook(PIO_DISPATCH_HEADER pIoDispatchHead)
{
    HANDLE hThread;
    KdBreakPoint();

    if(NtInformations.Initialized == FALSE||
    NtInformations.PspCreateProcess == NULL||
    NtInformations.NtCreateProcess == NULL ||
    NtInformations.NtCreateProcessEx == NULL ||
    NtInformations.NtCreateUserProcess == NULL ||
    NtInformations.NtShutdownSystem == NULL)
    {
        pIoDispatchHead->Body.Status = STATUS_INVALID_PARAMETER;
    }
    /*
    // Hook PspCreateProcess
    if (HkCreateInlineHook((PVOID)NtInformations.PspCreateProcess,
                           (PVOID)Fake_PspCreateProcess,
                           (PVOID *)&Old_PspCreateProcess,
                           &HkHandlePspCreateProcess))
    {
        if(HkEnableInlineHook(HkHandlePspCreateProcess))
        {
            KdPrint(("[Log] Hook PspCreateProcess success\n"));
        }
    }
    
    //Hook NtCreateProcess
    if (HkCreateInlineHook((PVOID)NtInformations.NtCreateProcess,
                           (PVOID)Fake_NtCreateProcess,
                           (PVOID *)&Old_NtCreateProcess,
                           &HkHandleNtCreateProcess))
    {
        if(HkEnableInlineHook(HkHandleNtCreateProcess))
        {
            KdPrint(("[Log] Hook NtCreateProcess success\n"));
        }
    }

    //Hook NtCreateProcessEx
    if (HkCreateInlineHook((PVOID)NtInformations.NtCreateProcessEx,
                           (PVOID)Fake_NtCreateProcessEx,
                           (PVOID *)&Old_NtCreateProcessEx,
                           &HkHandleNtCreateProcessEx))
    {
        if(HkEnableInlineHook(HkHandleNtCreateProcessEx))
        {
            KdPrint(("[Log] Hook NtCreateProcessEx success\n"));
        }
    }

    //Hook NtCreateUserProcess
    if (HkCreateInlineHook((PVOID)NtInformations.NtCreateUserProcess,
                           (PVOID)Fake_NtCreateUserProcess,
                           (PVOID *)&Old_NtCreateUserProcess,
                           &HkHandleNtCreateUserProcess))
    {
        if(HkEnableInlineHook(HkHandleNtCreateUserProcess))
        {
            KdPrint(("[Log] Hook NtCreateUserProcess success\n"));
        }
    }
    
    
    //Hook NtCreateFile
    if (HkCreateInlineHook((PVOID)NtInformations.NtCreateFile,
                           (PVOID)Fake_NtCreateFile,
                           (PVOID *)&Old_NtCreateFile,
                           &HkHandleNtCreateFile))
    {
        if(HkEnableInlineHook(HkHandleNtCreateFile))
        {
            KdPrint(("[Log] Hook NtCreateFile success\n"));
        }
    }

     //Hook NtShutdownSystem
    if (HkCreateInlineHook((PVOID)NtInformations.NtShutdownSystem,
                           (PVOID)Fake_NtShutdownSystem,
                           (PVOID *)&Old_NtShutdownSystem,
                           &HkHandleNtShutdownSystem))
    {
        if(HkEnableInlineHook(HkHandleNtShutdownSystem))
        {
            KdPrint(("[Log] Hook NtShutdownSystem success\n"));
        }
    }*/

    // set io status
    pIoDispatchHead->Body.Status = STATUS_SUCCESS;
}

NTSTATUS Fake_NtCreateProcess(__out PHANDLE ProcessHandle,
                              __in ACCESS_MASK DesiredAccess,
                              __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
                              __in HANDLE ParentProcess,
                              __in BOOLEAN InheritObjectTable,
                              __in_opt HANDLE SectionHandle,
                              __in_opt HANDLE DebugPort,
                              __in_opt HANDLE ExceptionPort)
{
    PSYMBOL_MAP_ITEM_INFO pItem;
    PEPROCESS ParendProcess;
    PUNICODE_STRING pImageFileName;
    pItem = NtExGetStructChildInfo("_EPROCESS", "SeAuditProcessCreationInfo");
    if (NT_SUCCESS(ObReferenceObjectByHandle(ParentProcess, GENERIC_ALL, *PsProcessType, KernelMode, &ParendProcess, NULL)))
    {
        if (pItem != NULL)
        {
            pImageFileName = (PUNICODE_STRING) * (PDWORD64)((DWORD64)ParendProcess + pItem->Offset);
            KdPrint(("NtCreateProcess %wZ\n", pImageFileName));
        }
        ObDereferenceObject(ParendProcess);
    }
    return Old_NtCreateProcess(ProcessHandle,
                               DesiredAccess,
                               ObjectAttributes,
                               ObjectAttributes,
                               InheritObjectTable,
                               SectionHandle,
                               DebugPort,
                               ExceptionPort);
}

NTSTATUS Fake_NtCreateProcessEx(__out PHANDLE ProcessHandle,
                                __in ACCESS_MASK DesiredAccess,
                                __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
                                __in HANDLE ParentProcess,
                                __in ULONG Flags,
                                __in_opt HANDLE SectionHandle,
                                __in_opt HANDLE DebugPort,
                                __in_opt HANDLE ExceptionPort,
                                __in ULONG JobMemberLevel)
{
    PSYMBOL_MAP_ITEM_INFO pItem;
    PEPROCESS ParendProcess;
    PUNICODE_STRING pImageFileName;

    pItem = NtExGetStructChildInfo("_EPROCESS", "SeAuditProcessCreationInfo");
    if (NT_SUCCESS(ObReferenceObjectByHandle(ParentProcess, GENERIC_ALL, *PsProcessType, KernelMode, &ParendProcess, NULL)))
    {
        if (pItem != NULL)
        {
            pImageFileName = (PUNICODE_STRING) * (PDWORD64)((DWORD64)ParendProcess + pItem->Offset);
            KdPrint(("NtCreateProcessEx %wZ\n", pImageFileName));
        }

        ObDereferenceObject(ParendProcess);
    }

    return Old_NtCreateProcessEx(ProcessHandle,
                                 DesiredAccess,
                                 ObjectAttributes,
                                 ParentProcess,
                                 Flags,
                                 SectionHandle,
                                 DebugPort,
                                 ExceptionPort,
                                 JobMemberLevel);
}

NTSTATUS Fake_PspCreateProcess(OUT PHANDLE ProcessHandle,
                               IN ACCESS_MASK DesiredAccess,
                               IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                               IN HANDLE ParentProcess OPTIONAL,
                               IN ULONG Flags,
                               IN HANDLE SectionHandle OPTIONAL,
                               IN HANDLE DebugPort OPTIONAL,
                               IN HANDLE ExceptionPort OPTIONAL,
                               IN ULONG JobMemberLevel)
{
    PSYMBOL_MAP_ITEM_INFO pItem;
    PEPROCESS ParendProcess;
    PUNICODE_STRING pImageFileName;

    pItem = NtExGetStructChildInfo("_EPROCESS", "SeAuditProcessCreationInfo"); 
    if (NT_SUCCESS(ObReferenceObjectByHandle(ParentProcess, GENERIC_ALL, *PsProcessType, KernelMode, &ParendProcess, NULL)))
    {
        if (pItem != NULL)
        {
            pImageFileName = (PUNICODE_STRING)*(PDWORD64)((DWORD64)ParendProcess + pItem->Offset);
            KdPrint(("PspCreateProcess %wZ\n", pImageFileName));
        }

        ObDereferenceObject(ParendProcess);
    }

    return Old_PspCreateProcess(ProcessHandle,
                                DesiredAccess,
                                ObjectAttributes,
                                ParentProcess,
                                Flags,
                                SectionHandle,
                                DebugPort,
                                ExceptionPort,
                                JobMemberLevel);
}

NTSTATUS Fake_NtCreateUserProcess(OUT PHANDLE ProcessHandle,
                                  OUT PHANDLE ThreadHandle,
                                  IN ACCESS_MASK ProcessDesiredAccess,
                                  IN ACCESS_MASK ThreadDesiredAccess,
                                  IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
                                  IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
                                  IN ULONG CreateProcessFlags,
                                  IN ULONG CreateThreadFlags,
                                  IN PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
                                  IN PVOID Parameter9,
                                  IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList)
{
    if(ProcessParameters->ImagePathName.Buffer != NULL)
    {
        KdPrint(("NtCreateUserProcess ImageFileName: %wZ \n",
                 &ProcessParameters->ImagePathName));
    }
    if(ProcessParameters->CommandLine.Buffer != NULL)
    {
        KdPrint(("CmdLine: %wZ \n",
                 &ProcessParameters->CommandLine));
    }
    
    return Old_NtCreateUserProcess(ProcessHandle,
                                   ThreadHandle,
                                   ProcessDesiredAccess,
                                   ThreadDesiredAccess,
                                   ProcessObjectAttributes,
                                   ThreadObjectAttributes,
                                   CreateProcessFlags,
                                   CreateThreadFlags,
                                   ProcessParameters,
                                   Parameter9,
                                   AttributeList);
}

NTSTATUS Fake_NtCreateFile(__out PHANDLE FileHandle,
                           __in ACCESS_MASK DesiredAccess,
                           __in POBJECT_ATTRIBUTES ObjectAttributes,
                           __out PIO_STATUS_BLOCK IoStatusBlock,
                           __in_opt PLARGE_INTEGER AllocationSize,
                           __in ULONG FileAttributes,
                           __in ULONG ShareAccess,
                           __in ULONG CreateDisposition,
                           __in ULONG CreateOptions,
                           __in PVOID EaBuffer,
                           __in ULONG EaLength)
{
    
   
    return Old_NtCreateFile(FileHandle,
                            DesiredAccess,
                            ObjectAttributes,
                            IoStatusBlock,
                            AllocationSize,
                            FileAttributes,
                            ShareAccess,
                            CreateDisposition,
                            CreateOptions,
                            EaBuffer,
                            EaLength);
}

NTSTATUS Fake_NtShutdownSystem(SHUTDOWN_ACTION Parameters)
{
    PEPROCESS pEprocess;
    UNICODE_STRING ImageFileName;
    pEprocess = PsGetCurrentProcess();
    if(NtExGetProcessFileName(pEprocess,&ImageFileName) && ImageFileName.Buffer != NULL)
    {
        KdPrint(("%wZ Will Shutdown System\n",&ImageFileName));
        ExFreePool(ImageFileName.Buffer);
        ImageFileName.Length = 0;
        ImageFileName.MaximumLength = 0;
    }
    return STATUS_INVALID_PARAMETER;
}