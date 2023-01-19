
#ifndef IO_DISPATCH_HEAD
#define IO_DISPATCH_HEAD

#include <ntddk.h>

#pragma once

#pragma pack(push, 1)
// Define IO dispatch body
typedef struct _IO_DISPATCH_BODY{
	INT32 Cmd;			// Command
	INT32 Cmd2;			// Command option
	PVOID InBuff;		// Input buffer from ring3
	DWORD32 InBuffLen;	// Input buffer length
	PVOID OutBuff;		// Out put buffer
	DWORD32 OutBuffLen;	// Out put buffer length
	NTSTATUS Status;	// Io Status	
}IO_DISPATCH_BODY, *PIO_DISPATCH_BODY;

// Define IO dispatch header
typedef struct _IO_DISPATCH_HEADER
{
	DWORD32 Version;		// Version
	DWORD32 SizeOfHeader;	// Dispatch header size
	IO_DISPATCH_BODY Body;	// Dispatch body see IO_DISPATCH_BODY
}IO_DISPATCH_HEADER, *PIO_DISPATCH_HEADER;
#pragma pack(pop)
// Define Dispatch routine
typedef VOID IO_DISPATCH_ROUTINE (PIO_DISPATCH_HEADER);
typedef IO_DISPATCH_ROUTINE* PIO_DISPATCH_ROUTINE;

// Max number of dispatch routine 
#define IO_NUMBER_OF_DISPATCH_ROUTINE 64

// This array storage dispatch routine
EXTERN_C PIO_DISPATCH_ROUTINE IoDispatchRoutine[IO_NUMBER_OF_DISPATCH_ROUTINE];

// This function will be insert dispatch routine to routine array
// Parameters:
//		Routine			[In]	Dispatch routine
//		Cmd				[In]	Index of array
BOOLEAN IoDispatchInsertRoutine(PIO_DISPATCH_ROUTINE Routine, INT32 Cmd);

// This funciton will be delete dispatch routine from routine array
// Parameters:
//		Cmd				[In]	Index of array
BOOLEAN IoDispatchDeleteRoutine(INT32 Cmd);

// Call dispatch routine
// This function use Index call the dispatch routine from dispatch header
// Parameters:
//		pHead			[In]	A pointer to the dispatch header
BOOLEAN IoDispatchCallRoutine(PIO_DISPATCH_HEADER pHead);

#endif