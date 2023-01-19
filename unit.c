#include "unit.h"

BOOLEAN InitializationUnit()
{
	if (MemInitializeBlockList())
	{
		if (NtExInitialization())
		{
			if (HkInitializaInlineHook())
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOLEAN UnInitializationUnit()
{
	if (HkUnInitializaInlineHook())
	{
		if (NtExUnInitialization())
		{
			if (MemInitializeBlockList())
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}
