
#include "io_dispatch.h"

PIO_DISPATCH_ROUTINE IoDispatchRoutine[IO_NUMBER_OF_DISPATCH_ROUTINE] = {NULL};

#pragma alloc_text(PAGE,IoDispatchInsertRoutine)
#pragma alloc_text(PAGE,IoDispatchDeleteRoutine)
#pragma alloc_text(PAGE,IoDispatchCallRoutine)

BOOLEAN IoDispatchInsertRoutine(PIO_DISPATCH_ROUTINE Routine, INT32 Cmd)
{
	PAGED_CODE();

	if (!MmIsAddressValid((PVOID)(ULONG_PTR)Routine))
	{
		return FALSE;
	}
	if ((Cmd < 0) || (Cmd >= IO_NUMBER_OF_DISPATCH_ROUTINE))
	{
		return FALSE;
	}
	IoDispatchRoutine[Cmd] = Routine;
	return FALSE;
}

BOOLEAN IoDispatchDeleteRoutine(INT32 Cmd)
{
	PAGED_CODE();

	if (Cmd < 0 || Cmd >= IO_NUMBER_OF_DISPATCH_ROUTINE)
	{
		return FALSE;
	}
	IoDispatchRoutine[Cmd] = NULL;
	return TRUE;
}

BOOLEAN IoDispatchCallRoutine(PIO_DISPATCH_HEADER pHead)
{
	PAGED_CODE();
	
	if (pHead == NULL)
	{
		return FALSE;
	}
	if (pHead->Body.Cmd < 0 || pHead->Body.Cmd >= IO_NUMBER_OF_DISPATCH_ROUTINE)
	{
		return FALSE;
	}
	if (!MmIsAddressValid((PVOID)(ULONG_PTR)IoDispatchRoutine[pHead->Body.Cmd]))
	{
		return FALSE;
	}
	IoDispatchRoutine[pHead->Body.Cmd](pHead);
	return TRUE;
}
