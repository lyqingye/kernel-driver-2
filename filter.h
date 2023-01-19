
#ifndef FILTER_HEAD
#define FILTER_HEAD

#include "unit.h"

VOID 
FtInitializationHook(PIO_DISPATCH_HEADER pIoDispatchHead);

NTSTATUS
Fake_PspCreateProcess(OUT PHANDLE ProcessHandle,
                      IN ACCESS_MASK DesiredAccess,
                      IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
                      IN HANDLE ParentProcess OPTIONAL,
                      IN ULONG Flags,
                      IN HANDLE SectionHandle OPTIONAL,
                      IN HANDLE DebugPort OPTIONAL,
                      IN HANDLE ExceptionPort OPTIONAL,
                      IN ULONG JobMemberLevel);

NTSTATUS Fake_NtCreateProcess(__out PHANDLE ProcessHandle,
                              __in ACCESS_MASK DesiredAccess,
                              __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
                              __in HANDLE ParentProcess,
                              __in BOOLEAN InheritObjectTable,
                              __in_opt HANDLE SectionHandle,
                              __in_opt HANDLE DebugPort,
                              __in_opt HANDLE ExceptionPort);

                              
NTSTATUS Fake_NtCreateProcessEx(__out PHANDLE ProcessHandle,
                                __in ACCESS_MASK DesiredAccess,
                                __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
                                __in HANDLE ParentProcess,
                                __in ULONG Flags,
                                __in_opt HANDLE SectionHandle,
                                __in_opt HANDLE DebugPort,
                                __in_opt HANDLE ExceptionPort,
                                __in ULONG JobMemberLevel);

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
                                  IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList);

                                  
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
                           __in ULONG EaLength);

NTSTATUS Fake_NtShutdownSystem(SHUTDOWN_ACTION Parameters);

#endif