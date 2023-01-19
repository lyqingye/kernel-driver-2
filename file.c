#include "file.h"
  
NTSTATUS FLCreateFileW(PUNICODE_STRING pWszFileName, ACCESS_MASK DesiredAccess, ULONG CreateDispostion, PHANDLE pFileHandle, PIO_STATUS_BLOCK pIoStatusBlock)
{
	OBJECT_ATTRIBUTES ObjectAttr;

	RtlZeroMemory((PVOID)&ObjectAttr, sizeof(OBJECT_ATTRIBUTES));

	InitializeObjectAttributes(&ObjectAttr, pWszFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	return ZwCreateFile(pFileHandle, 
						DesiredAccess,
						&ObjectAttr,
						pIoStatusBlock,
						NULL, 
						FILE_ATTRIBUTE_NORMAL, 
						FILE_SHARE_DELETE | 
						FILE_SHARE_READ | 
						FILE_SHARE_WRITE,
						CreateDispostion, 
						FILE_NON_DIRECTORY_FILE | 
						FILE_RANDOM_ACCESS| 
						FILE_SYNCHRONOUS_IO_NONALERT,
						NULL, 
						0);
}

NTSTATUS FLReadFile(HANDLE FileHandle, PMEM_BLOCK_LIST pMemoryBlock, ULONG Length, PIO_STATUS_BLOCK pIoStatusBlock)
{
	LARGE_INTEGER Offset = {0};

	if (pMemoryBlock == NULL || pMemoryBlock->Buffer == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	if (pMemoryBlock->Size < Length)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return ZwReadFile(FileHandle,
					  NULL,
					  NULL,
					  NULL,
					  pIoStatusBlock,
					  pMemoryBlock->Buffer,
					  Length,
					  &Offset,
					  NULL);
}

NTSTATUS FLReadFileAndAllocate(HANDLE FileHandle, PMEM_BLOCK_LIST * ppMemoryBlock, ULONG Length, PIO_STATUS_BLOCK pIoStatusBlock)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	FILE_STANDARD_INFORMATION fsi = { 0 };

	if (ppMemoryBlock == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	status = ZwQueryInformationFile(FileHandle, pIoStatusBlock, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	if (NT_SUCCESS(status))
	{
		if (fsi.EndOfFile.QuadPart == 0)
		{
			return STATUS_FILE_INVALID;
		}
		*ppMemoryBlock = ExLockMemAllocateBlock(NonPagedPool, fsi.EndOfFile.QuadPart);

		if (*ppMemoryBlock == NULL || (*ppMemoryBlock)->Buffer == NULL || (*ppMemoryBlock)->Size < Length)
		{
			return STATUS_NO_MEMORY;
		}

		if (Length == -1)
		{
			return FLReadFile(FileHandle, *ppMemoryBlock, (ULONG)(*ppMemoryBlock)->Size, pIoStatusBlock);
		}
		else
		{
			return FLReadFile(FileHandle, *ppMemoryBlock, Length, pIoStatusBlock);
		}
	}
	else
	{
		return status;
	}
}

NTSTATUS FLWriteFile(PUNICODE_STRING pWszFileName, PMEM_BLOCK_LIST pMemoryBlock, ULONG Length, PIO_STATUS_BLOCK pIoStatusBlock)
{
	HANDLE FileHandle;
	LARGE_INTEGER offset = {0};
	OBJECT_ATTRIBUTES ObjectAttr;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	
	if (pMemoryBlock == NULL || pMemoryBlock->Buffer == NULL || pMemoryBlock->Size < Length)
	{
		return STATUS_INVALID_PARAMETER;
	}

	RtlZeroMemory((PVOID)&ObjectAttr, sizeof(OBJECT_ATTRIBUTES));

	InitializeObjectAttributes(&ObjectAttr, pWszFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = FLCreateFileW(pWszFileName, GENERIC_WRITE, FILE_OPEN_IF, &FileHandle, pIoStatusBlock);
	if (NT_SUCCESS(status))
	{
		status = ZwWriteFile(FileHandle,
						     NULL, 
					         NULL,
						     NULL, 
						     pIoStatusBlock, 
						     pMemoryBlock->Buffer, 
						     Length,
						     &offset,
						     NULL);
		FLCloseFile(FileHandle);
		return status;
	}
	else
	{
		return status;
	}
}

NTSTATUS FLCloseFile(HANDLE FileHandle)
{
	return ZwClose(FileHandle);
}
