#include "pe.h"

BOOLEAN PeAnalysisFromDiskFileBuffer(PMEM_BLOCK_LIST pMemBlk, PPE_ANALYSIS_INFO pAnalysisInfo)
{
	UINT Foa = 0;
	PUCHAR pFileBuffer = NULL;
	PPE_IMAGE_DOS_HEADER pDosHead = NULL;
	PPE_IMAGE_NT_HEADERS32 pNtHeads32 = NULL;
	PPE_IMAGE_NT_HEADERS64 pNtHeads64 = NULL;
	PPE_IMAGE_FILE_HEADER  pFileHead = NULL;
	PPE_IMAGE_OPTIONAL_HEADER32 pOptionHead32 = NULL;
	PPE_IMAGE_OPTIONAL_HEADER64 pOptionHead64 = NULL;

	if (pMemBlk == NULL || pMemBlk->Buffer == NULL || pAnalysisInfo == NULL)
	{
		return FALSE;
	}

	if (pMemBlk->Size < sizeof(PE_IMAGE_DOS_HEADER))
	{
		return FALSE;
	}

	RtlZeroMemory((PVOID)pAnalysisInfo, sizeof(PE_ANALYSIS_INFO));

	pAnalysisInfo->pFileMemBlock = pMemBlk;
	pFileBuffer = pMemBlk->Buffer;

	pDosHead = (PPE_IMAGE_DOS_HEADER)pFileBuffer;;
	if (pDosHead->e_magic != 0x5A4D)
	{
		return FALSE;
	}
	if (pMemBlk->Size < pDosHead->e_lfanew + sizeof(PE_IMAGE_NT_HEADERS32))
	{
		return FALSE;
	}
	if (pMemBlk->Size < pDosHead->e_lfanew + sizeof(PE_IMAGE_NT_HEADERS64))
	{
		return FALSE;
	}
	pNtHeads32 = (PPE_IMAGE_NT_HEADERS32)(pFileBuffer + pDosHead->e_lfanew);
	pNtHeads64 = (PPE_IMAGE_NT_HEADERS64)(pFileBuffer + pDosHead->e_lfanew);
	if (pNtHeads32->Signature != 0x00004550)
	{
		return FALSE;
	}
	pFileHead = (PPE_IMAGE_FILE_HEADER)&pNtHeads32->FileHeader;
	pOptionHead32 = (PPE_IMAGE_OPTIONAL_HEADER32)&pNtHeads32->OptionalHeader;
	pOptionHead64 = (PPE_IMAGE_OPTIONAL_HEADER64)&pNtHeads64->OptionalHeader;

	pAnalysisInfo->pDosHead = pDosHead;
	pAnalysisInfo->pFileHead = pFileHead;
	pAnalysisInfo->Machine = pFileHead->Machine;
	pAnalysisInfo->NumOfSections = pFileHead->NumberOfSections;
	if (pFileHead->Machine == 0x014c)
	{
		pAnalysisInfo->pNtHeads32 = pNtHeads32;
		pAnalysisInfo->pOptionHead32 = pOptionHead32;

		pAnalysisInfo->pSecHead = (PPE_IMAGE_SECTION_HEADER)
								  (pOptionHead32->SizeOfHeaders + pFileBuffer);

		if (PeUnitRvaToFoa((PEHANDLE)pAnalysisInfo, pOptionHead32->DataDirectory[0].VirtualAddress, &Foa))
		{
			pAnalysisInfo->pExportDirectory = (PPE_IMAGE_EXPORT_DIRECTORY)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}
		
		if (PeUnitRvaToFoa((PEHANDLE)pAnalysisInfo, pOptionHead32->DataDirectory[1].VirtualAddress, &Foa))
		{
			pAnalysisInfo->pImportDescriptor = (PPE_IMAGE_IMPORT_DESCRIPTOR)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}

		if (PeUnitRvaToFoa((PEHANDLE)pAnalysisInfo, pOptionHead64->DataDirectory[5].VirtualAddress, &Foa))
		{
			pAnalysisInfo->pRelocation = (PPE_IMAGE_BASE_RELOCATION)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}
	}
	else if (pFileHead->Machine == 0x8664)
	{
		
		pAnalysisInfo->pNtHeads64 = pNtHeads64;
		pAnalysisInfo->pOptionHead64 = pOptionHead64;

		pAnalysisInfo->pSecHead = (PPE_IMAGE_SECTION_HEADER)
								  (pOptionHead64->SizeOfHeaders + pFileBuffer);

		if (PeUnitRvaToFoa((PEHANDLE)pAnalysisInfo, pOptionHead64->DataDirectory[0].VirtualAddress, &Foa))
		{
			pAnalysisInfo->pExportDirectory = (PPE_IMAGE_EXPORT_DIRECTORY)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}

		if (PeUnitRvaToFoa((PEHANDLE)pAnalysisInfo, pOptionHead64->DataDirectory[1].VirtualAddress, &Foa))
		{
			pAnalysisInfo->pImportDescriptor = (PPE_IMAGE_IMPORT_DESCRIPTOR)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}

		if (PeUnitRvaToFoa((PEHANDLE)pAnalysisInfo, pOptionHead64->DataDirectory[5].VirtualAddress, &Foa))
		{
			pAnalysisInfo->pRelocation = (PPE_IMAGE_BASE_RELOCATION)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}
	}
	pAnalysisInfo->Initialized = TRUE;
	return TRUE;
}

BOOLEAN PeUnitRvaToFoa(PEHANDLE Handle, UINT Rva, PUINT pFoa)
{
	UINT i;
	PPE_IMAGE_SECTION_HEADER pSection = NULL;

	if (Handle == NULL || pFoa == NULL)
	{
		return FALSE;
	}

#ifdef DBG
	ASSERT(Handle->NumOfSections > 0);
#endif

	pSection = Handle->pSecHead;

	if (pSection)
	{
		for (i = 0; i < Handle->NumOfSections; i++)
		{
			if (Rva >= pSection->VirtualAddress && Rva <= pSection->VirtualAddress +
				max(pSection->Misc.VirtualSize, pSection->SizeOfRawData))
			{
				*pFoa = Rva - pSection->VirtualAddress + pSection->PointerToRawData;
				return TRUE;
			}
			pSection++;
		}
	}
	return FALSE;
}

BOOLEAN PeEnumSection(PEHANDLE Handle, PVOID Parameter, PENUM_SECTION_ROUTINE pEnumRoutine)
{
	UINT Index = 0;
	PPE_IMAGE_SECTION_HEADER pSection = NULL;

	if (Handle == NULL || Handle->Initialized == FALSE)
	{
		return FALSE;
	}

	if (pEnumRoutine == NULL)
	{
		return FALSE;
	}

#ifdef DBG
	ASSERT(Handle->NumOfSections > 0);
#endif

	pSection = Handle->pSecHead;

	for (Index; Index < Handle->NumOfSections; Index++)
	{
		pEnumRoutine(pSection++, Index, Parameter);
	}
	return TRUE;
}

BOOLEAN PeEnumExportTable(PEHANDLE Handle, PVOID Parameter, PENUM_EXPORT_ROUTINE pEnumRoutine)
{
	UINT   Foa = 0;
	UINT   i, j, Base;
	PWORD  OrdinalAddr = 0;
	PUINT  NameAddr = 0;
	PUINT  FuncAddr = 0;
	PUCHAR pFileBuffer = NULL;

	PE_ENUM_EXPORT_INFO EnumInfo;
	PPE_IMAGE_EXPORT_DIRECTORY pExpTable = NULL;

	RtlZeroMemory((PVOID)&EnumInfo, sizeof(PE_ENUM_EXPORT_INFO));
	EnumInfo.ExtraInfo.Parameter = Parameter;
	if (Handle == NULL || pEnumRoutine == NULL || Handle->Initialized == FALSE)
	{
		return FALSE;
	}

	pFileBuffer = (PUCHAR)Handle->pFileMemBlock->Buffer;
	pExpTable = Handle->pExportDirectory;

	if ((PVOID)pExpTable == (PVOID)pFileBuffer)
	{
		// No Table
		return FALSE;
	}

	Base = pExpTable->Base;
	if (PeUnitRvaToFoa(Handle, pExpTable->AddressOfNames, &Foa))
	{
		NameAddr = (PUINT)(Foa + pFileBuffer);
	}
	else
	{
		return FALSE;
	}

	if (PeUnitRvaToFoa(Handle, pExpTable->AddressOfFunctions, &Foa))
	{
		FuncAddr = (PUINT)(Foa + pFileBuffer);
	}
	else
	{
		return FALSE;
	}

	if (PeUnitRvaToFoa(Handle, pExpTable->AddressOfNameOrdinals, &Foa))
	{
		OrdinalAddr = (PWORD)(Foa + pFileBuffer);
	}
	else
	{
		return FALSE;
	}

	for (i = 0; i < pExpTable->NumberOfFunctions; i++)
	{
		EnumInfo.pFuncAddrRva = FuncAddr;
		
		for (j = 0; j < pExpTable->NumberOfNames; j++)
		{
			if ((Base + i) == (*(OrdinalAddr + j) + Base))
			{
				EnumInfo.pIndexRva = OrdinalAddr + j;
				EnumInfo.pNameRva = NameAddr + j;
				break;
			}
		}

		if (j == pExpTable->NumberOfNames)
		{
			EnumInfo.pNameRva = 0;
			EnumInfo.ExtraInfo.pName = NULL;
		}
		else
		{
			if (PeUnitRvaToFoa(Handle, *(EnumInfo.pNameRva), &Foa))
			{
				EnumInfo.ExtraInfo.pName = (PCHAR)(Foa + pFileBuffer);
			}
		}
			
		if (pEnumRoutine(&EnumInfo) == FALSE)
			return TRUE;

		FuncAddr++;
	}
	return TRUE;
}

BOOLEAN PeEnumImportTable(PEHANDLE Handle, PVOID Parameter, PENUM_IMPORT_ROUTINE pEnumRoutine)
{
	UINT  Foa = 0;
	PUINT pThunk, pIat;
	PUCHAR pFileBuffer = NULL;
	PPE_IMAGE_IMPORT_DESCRIPTOR	pDllInfo = NULL;
	PE_ENUM_IMPORT_INFO	EnumInfo;
	
	RtlZeroMemory((PVOID)&EnumInfo, sizeof(PE_ENUM_IMPORT_INFO));
	EnumInfo.ExtraInfo.Parameter = Parameter;
	if (Handle == NULL || pEnumRoutine == NULL || Handle->Initialized == FALSE)
	{
		return FALSE;
	}

	pFileBuffer = (PUCHAR)Handle->pFileMemBlock->Buffer;
	pDllInfo = Handle->pImportDescriptor;

	if ((PVOID)pFileBuffer == (PVOID)pDllInfo)
	{
		// No Table
		return FALSE;
	}

	EnumInfo.DllIndex = 0;

	while (pDllInfo->FirstThunk != 0 &&
		   pDllInfo->Name != 0 &&
		   pDllInfo->OriginalFirstThunk != 0)
	{
		EnumInfo.pDllInfo = pDllInfo;
		
		if (pDllInfo->FirstThunk == 0 || pDllInfo->OriginalFirstThunk == 0)
		{
			return FALSE;
		}

		if (PeUnitRvaToFoa(Handle, pDllInfo->FirstThunk, &Foa))
		{
			pIat = (PUINT)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}
	
		if (PeUnitRvaToFoa(Handle, pDllInfo->OriginalFirstThunk, &Foa))
		{
			pThunk = (PUINT)(Foa + pFileBuffer);
		}
		else
		{
			return FALSE;
		}
		
		if (PeUnitRvaToFoa(Handle, pDllInfo->Name, &Foa))
		{
			EnumInfo.ExtraInfo.pDllName = (PCHAR)(pFileBuffer + Foa);
		}
		else
		{
			return FALSE;
		}

		while (*pThunk)
		{
			if (Handle->Machine == 0x014c)
			{
				if (IMAGE_SNAP_BY_ORDINAL32(*pThunk))
				{
					EnumInfo.pFuncNameRva = 0;
					EnumInfo.ExtraInfo.pFuncName = NULL;
				}
				else
				{
					EnumInfo.pFuncNameRva = pThunk;
				}
				EnumInfo.Hit = IMAGE_ORDINAL32(*pThunk);
			}
			else if (Handle->Machine == 0x8664)
			{
				if (IMAGE_SNAP_BY_ORDINAL64(*pThunk))
				{
					EnumInfo.pFuncNameRva = 0;
					EnumInfo.ExtraInfo.pFuncName = NULL;
				}
				else
				{
					EnumInfo.pFuncNameRva = pThunk;
					
				}
				EnumInfo.Hit = IMAGE_ORDINAL64(*pThunk);
				if (EnumInfo.pFuncNameRva)
				{
					if (PeUnitRvaToFoa(Handle, *(EnumInfo.pFuncNameRva), &Foa))
					{
						EnumInfo.ExtraInfo.pFuncName = (PCHAR)(&((PIMAGE_IMPORT_BY_NAME)(pFileBuffer + Foa))->Name);
					}
				}
			}
			EnumInfo.pIat = pIat;
			EnumInfo.pThunk = pThunk;

			if (pEnumRoutine(&EnumInfo) == FALSE)
			{
				return TRUE;
			}
			pThunk++;
			pIat++;
		}
		pDllInfo++;
		EnumInfo.DllIndex++;
	}
	return TRUE;
}

BOOLEAN PeEnumRelocationTable(PEHANDLE Handle, PVOID Parameter, PENUM_RELOCATION_ROUTINE pEnumRoutine)
{
	UINT Foa = 0;
	PWORD Blk, BlkEnd;
	PUCHAR pFileBuffer = NULL;
	PE_ENUM_RELOCATION_INFO EnumInfo;
	PPE_IMAGE_BASE_RELOCATION BlkInfo = NULL;

	RtlZeroMemory((PVOID)&EnumInfo, sizeof(PE_IMAGE_BASE_RELOCATION));
	EnumInfo.ExtraInfo.Parameter = Parameter;
	if (Handle == NULL || pEnumRoutine == NULL || Handle->Initialized == FALSE)
	{
		return FALSE;
	}

	pFileBuffer = (PUCHAR)(Handle->pFileMemBlock->Buffer);
	BlkInfo = Handle->pRelocation;

	if ((PVOID)BlkInfo == (PVOID)pFileBuffer)
	{
		// No Table
		return FALSE;
	}

	EnumInfo.RelIndex = 0;

	while (BlkInfo->VirtualAddress != 0 &&
		BlkInfo->SizeOfBlock != 0)
	{
		EnumInfo.pRelocation = BlkInfo;

		Blk = (PWORD)((PUCHAR)BlkInfo + sizeof(PE_IMAGE_BASE_RELOCATION));
		BlkEnd = (PWORD)((PUCHAR)BlkInfo + BlkInfo->SizeOfBlock);

		while (Blk != BlkEnd)
		{
			EnumInfo.ExtraInfo.Type = PE_RELOCA_FLAG(*Blk);
			EnumInfo.pItem = Blk;
			EnumInfo.ExtraInfo.Rva = BlkInfo->VirtualAddress + PE_RELOCA_RVA(*Blk);

			if (PeUnitRvaToFoa(Handle, EnumInfo.ExtraInfo.Rva, &Foa))
			{
				EnumInfo.ExtraInfo.Fa = (PVOID)(Foa + pFileBuffer);
			}
			else
			{
				return FALSE;
			}

			if (pEnumRoutine(&EnumInfo) == FALSE)
			{
				return TRUE;
			}
			Blk++;
		}

		BlkInfo = (PPE_IMAGE_BASE_RELOCATION)
				  ((PUCHAR)BlkInfo + BlkInfo->SizeOfBlock);

		EnumInfo.RelIndex++;
	} 
	return TRUE;
}
