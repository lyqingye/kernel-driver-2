
#ifndef TRAMPO_LINE_HEAD
#define TRAMPO_LINE_HEAD

#include "pstdint.h"
#include "mem.h"

#pragma once

#pragma pack(push, 1)
typedef struct _JMP_REL_SHORT
{
	UINT8  opcode;      // EB xx: JMP +2+xx
	UINT8  operand;
} JMP_REL_SHORT, *PJMP_REL_SHORT;

typedef struct _JMP_REL
{
	UINT8  opcode;      // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
	UINT32 operand;     // Relative destination address
} JMP_REL, *PJMP_REL, CALL_REL;

typedef struct _JMP_ABS
{
	UINT8  opcode0;     // FF25 00000000: JMP [+6]
	UINT8  opcode1;
	UINT32 dummy;
	UINT64 address;     // Absolute destination address
} JMP_ABS, *PJMP_ABS;

typedef struct _CALL_ABS
{
	UINT8  opcode0;     // FF15 00000002: CALL [+6]
	UINT8  opcode1;
	UINT32 dummy0;
	UINT8  dummy1;      // EB 08:         JMP +10
	UINT8  dummy2;
	UINT64 address;     // Absolute destination address
} CALL_ABS;

typedef struct _JCC_ABS
{
	UINT8  opcode;      // 7* 0E:         J** +16
	UINT8  dummy0;
	UINT8  dummy1;      // FF25 00000000: JMP [+6]
	UINT8  dummy2;
	UINT32 dummy3;
	UINT64 address;     // Absolute destination address
} JCC_ABS;

#pragma pack(pop)

typedef struct _TRAMPOLINE
{
	PVOID pTarget;          // [In] Address of the target function.     目标地址
	PVOID pDetour;          // [In] Address of the detour function.     转向地址
	PVOID pTrampoline;      // [In] Buffer address for the trampoline and relay function. 跳板地址

	PVOID pRelay;			// [Out] Address of the relay function.

	UINT8     nIP;          // [Out] Number of the instruction boundaries. 
	UINT8     oldIPs[8];    // [Out] Instruction boundaries of the target function.
	UINT8     newIPs[8];    // [Out] Instruction boundaries of the trampoline function.
	UINT8     sizeTramPoline;
} TRAMPOLINE, *PTRAMPOLINE;

BOOLEAN __fastcall HkUnitCreateTramPoline(PTRAMPOLINE pTramPoline);

#endif 
