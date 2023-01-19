#include "trampoline.h"
#include "hde64.h"

BOOLEAN HkUnitCreateTramPoline(PTRAMPOLINE pTramPoline)
{
	CALL_ABS call = {
		0xFF, 0x15, 0x00000002, // FF15 00000002: CALL [RIP+8]
		0xEB, 0x08,             // EB 08:         JMP +10
		0x0000000000000000ULL   // Absolute destination address
	};

	JMP_ABS jmp = {
		0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
		0x0000000000000000ULL   // Absolute destination address
	};

	JCC_ABS jcc = {
		0x70, 0x0E,             // 7* 0E:         J** +16
		0xFF, 0x25, 0x00000000, // FF25 00000000: JMP [RIP+6]
		0x0000000000000000ULL   // Absolute destination address
	};

	UINT8     oldPos = 0;
	UINT8     newPos = 0;
	ULONG_PTR jmpDest = 0;     // Destination address of an internal jump.
	BOOLEAN   finished = FALSE; // Is the function completed?
	UINT8     instBuf[64];

	if (pTramPoline == NULL || pTramPoline->pTarget == NULL || pTramPoline->pDetour == NULL || pTramPoline->pTrampoline == NULL)
		return FALSE;

	do
	{
		hde64s    hs;
		UINT8     InstSize;
		PVOID     pInstSrc;
		ULONG_PTR pOldInst = (ULONG_PTR)pTramPoline->pTarget + oldPos;
		ULONG_PTR pNewInst = (ULONG_PTR)pTramPoline->pTrampoline + newPos;

		try{
			InstSize = (UINT8)hde64_disasm((PVOID)pOldInst, &hs);
		}except(EXCEPTION_EXECUTE_HANDLER){
			return FALSE;
		}
		
		if (hs.flags & F_ERROR)
		{
			return FALSE;
		}

		pInstSrc = (PVOID)pOldInst;

		if (oldPos >= sizeof(JMP_ABS))
		{
			jmp.address = (UINT64)pInstSrc;
			pInstSrc = &jmp;
			InstSize = sizeof(JMP_ABS);
			finished = TRUE;
		}
		else if ((hs.modrm & 0xC7) == 0x05)
		{
			// Jmp qword ptr ds:[imm64] FF 25 00 00 00 00  4 BYTE OFFSET
			// imm64 = RIP + instruction len : 6  + offset
			// rel offset byte addr : RIP + 2
			// offset = imm64 - RIP - instruction len

			// will fix RIP get the new offset
			// RIP -> newRIP
			// newoffset = imm64 - newRIP - instruction len

			PUINT32 pRelAddr;

			RtlCopyMemory((PVOID)instBuf, (PVOID)pInstSrc, InstSize);
			pInstSrc = (PVOID)instBuf;

			pRelAddr = (PUINT32)(instBuf + hs.len - ((hs.flags & 0x3C) >> 2) - 4);
			*pRelAddr = (UINT32)((pOldInst + hs.len + (INT32)hs.disp.disp32) - (pNewInst + hs.len));

			// Jmp qword ptr ds:[imm64] 
			// finished ref inst
			// pTramPoline : Jmp qword ptr ds:[imm64] -> pTarget

			if (hs.opcode == 0xFF && hs.modrm_reg == 4)
			{
				finished = TRUE;
			}	
		}
		else if (hs.opcode == 0xE8) //CALL
		{
			// CALL imm64 E8 00 00 00 00 4BYTE OFFSET
			// imm64 = RIP + instruction len : 5 + offset

			// JMP [XXXX] XXXX -> imm64

			ULONG_PTR dest = pOldInst + hs.len + (INT32)hs.imm.imm32;
			call.address = dest;
			pInstSrc = &call;
			InstSize = sizeof(CALL_ABS);
		}
		else if ((hs.opcode & 0xFD) == 0xE9)
		{
			// imm64 = RIP + instruction len : 2 or 4 + offset
			ULONG_PTR dest = pOldInst + hs.len;

			// JMP imm64 EB 00 1BYTE OFFSET
			if (hs.opcode == 0xEB) // isShort jmp
				dest += (INT8)hs.imm.imm8; //EB 00
			else
				dest += (INT32)hs.imm.imm32;//E9 00 00 00 00

			if ((ULONG_PTR)pTramPoline->pTarget <= dest
				&& dest < ((ULONG_PTR)pTramPoline->pTarget + sizeof(JMP_REL)))
			{
				if (jmpDest < dest)
					jmpDest = dest;
			}
			else
			{
				jmp.address = dest;
				pInstSrc = &jmp;
				InstSize = sizeof(JMP_ABS);

				finished = (pOldInst >= jmpDest);
			}
		}
		else if ((hs.opcode & 0xF0) == 0x70
			|| (hs.opcode & 0xFC) == 0xE0
			|| (hs.opcode2 & 0xF0) == 0x80)
		{
			ULONG_PTR dest = pOldInst + hs.len;

			if ((hs.opcode & 0xF0) == 0x70      // Jcc
				|| (hs.opcode & 0xFC) == 0xE0)  // LOOPNZ/LOOPZ/LOOP/JECXZ
				dest += (INT8)hs.imm.imm8;
			else
				dest += (INT32)hs.imm.imm32;

			if ((ULONG_PTR)pTramPoline->pTarget <= dest
				&& dest < ((ULONG_PTR)pTramPoline->pTarget + sizeof(JMP_REL)))
			{
				if (jmpDest < dest)
					jmpDest = dest;
			}
			else if ((hs.opcode & 0xFC) == 0xE0)
			{
				// LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported.
				return FALSE;
			}
			else
			{
				UINT8 cond = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
				jcc.opcode = 0x71 ^ cond;
				jcc.address = dest;
				pInstSrc = &jcc;
				InstSize = sizeof(JCC_ABS);
			}
		}
		else if ((hs.opcode & 0xFE) == 0xC2)
		{
			// RET (C2 or C3)
			finished = (pOldInst >= jmpDest);
		}

		if (pOldInst < jmpDest && InstSize != hs.len)
			return FALSE;

		pTramPoline->oldIPs[pTramPoline->nIP] = oldPos; 
		pTramPoline->newIPs[pTramPoline->nIP] = newPos;
		pTramPoline->nIP++;

		RtlCopyMemory((PVOID)((PUCHAR)pTramPoline->pTrampoline + newPos), pInstSrc, InstSize);

		newPos += InstSize;
		oldPos += hs.len;
	} 
	while (!finished);

	jmp.address = (ULONG_PTR)pTramPoline->pDetour;
	pTramPoline->pRelay = (PVOID)((PUCHAR)pTramPoline->pTrampoline + newPos);

	RtlCopyMemory(pTramPoline->pRelay, (PVOID)&jmp, sizeof(JMP_ABS));

	pTramPoline->sizeTramPoline = newPos + sizeof(JMP_ABS);

	return TRUE;
}
