
#ifndef FILE_HEAD
#define FILE_HEAD

#include "pstdint.h"
#include "mem.h"

#pragma once

// This function will be create file.
// Don't Create directory
// Parameters:
//		pWszFileName		[In]	A pointer to the File Name Unicode string 
//		DesiredAccess		[In]	Access Mask
//		CreateDispostion	[In]	FILE_OPEN | FILE_OPEN_IF | FILE_CREATE | FILE_OVERWRITE |...
//		pFileHandle			[Out]	A pointer to the file handle
//		pIoStatusBlock		[Out]	A pointer to the io status block
NTSTATUS FLCreateFileW(PUNICODE_STRING pWszFileName,ACCESS_MASK DesiredAccess, ULONG CreateDispostion,PHANDLE pFileHandle, PIO_STATUS_BLOCK pIoStatusBlock);

// This function will be read file
// You must provide a memory block
// Parameters:
//		FileHandle			[In]	File Handle
//		pMemoryBlock		[In]	A pointer to the memory block
//		Length				[In]	Read length
//		pIoStatusBlock		[Out]	A pointer to the io status block
NTSTATUS FLReadFile(HANDLE FileHandle, PMEM_BLOCK_LIST pMemoryBlock,ULONG Length, PIO_STATUS_BLOCK pIoStatusBlock);

// This function will be read file And allocate file memory block
// Parameters:
//		FileHandle			[In]	File Handle
//		ppMemoryBlock		[Out]	A pointer to the memory block
//		Length				[In]	Read length,if values equeal -1 then read length is file size
//		pIoStatusBlock		[Out]	A pointer to the io status block
NTSTATUS FLReadFileAndAllocate(HANDLE FileHandle, PMEM_BLOCK_LIST *ppMemoryBlock, ULONG Length, PIO_STATUS_BLOCK pIoStatusBlock);

// This function will be write file
// Parameters:
//		pWszFileName		[In]	A pointer to the new file name unicode string 
//		pMemoryBlock		[In]	A pointer to the need write buffer
//		Length				[In]	Write length
//		pIoStatusBlock		[Out]	A pointer to the io status block
NTSTATUS FLWriteFile(PUNICODE_STRING pWszFileName, PMEM_BLOCK_LIST pMemoryBlock, ULONG Length, PIO_STATUS_BLOCK pIoStatusBlock);

// This function will be close file handle
// Parameters:
//		FileHandle			[In]	File Handle
NTSTATUS FLCloseFile(HANDLE FileHandle);

#endif